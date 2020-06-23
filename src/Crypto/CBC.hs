-- |
-- Module      : Crypto.CBC
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Utilities related to validation in a MAC-then-encrypt construction, like CBC
-- mode with SSL and TLS.
--
{-# LANGUAGE BangPatterns #-}
module Crypto.CBC
    ( segment
    , ssl
    , tls
    ) where

import           Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Compat (unsafeDoIO)
import           Crypto.Internal.Imports

import Data.Bits
import Data.Memory.PtrMethods

import Foreign.Ptr (Ptr)
import Foreign.Storable

msb :: Word -> Word
msb x = negate (x `unsafeShiftR` (finiteBitSize x - 1))

lt :: Word -> Word -> Word
lt a b = msb (a `xor` ((a `xor` b) .|. ((a - b) `xor` b)))

isZero :: Word -> Word
isZero x = msb (complement x .&. (x - 1))

eq :: Word -> Word -> Word
eq a b = isZero (a `xor` b)

eq8 :: Word -> Word -> Word8
eq8 a b = fromIntegral (eq a b)

orByteOff :: Ptr Word8 -> Int -> Word8 -> IO ()
orByteOff p i b = peekByteOff p i >>= \w -> pokeByteOff p i (w .|. b)

copyOffset :: Ptr Word8 -> Int -> Int -> Ptr Word8 -> Int -> IO ()
copyOffset src srcLen offset dst dstLen =
    memCreateTemporary dstLen $ \tmp -> memSet tmp 0 dstLen >> loop tmp 0 0 0 0
  where
    !dstLenW = fromIntegral dstLen
    !startW  = fromIntegral offset
    !endW    = startW + dstLenW

    wrap i = i .&. lt i dstLenW

    loop !tmp !inside !rotateOffset i !j
        | i >= srcLen = rotateOutput tmp rotateOffset
        | otherwise   = do
            let ui      = fromIntegral i
                started = eq ui startW
                ended   = lt ui endW
            b <- peekByteOff src i
            let inside'       = (inside .|. started) .&. ended
                rotateOffset' = rotateOffset .|. (j .&. started)
            orByteOff tmp (fromIntegral j) (b .&. fromIntegral inside')
            let j' = wrap (j + 1)
            loop tmp inside' rotateOffset' (i + 1) j'

    rotateOutput tmp rotateOffset = do
        memSet dst 0 dstLen
        let rotateOffset' = wrap (dstLenW - rotateOffset)
        rotateOuter tmp rotateOffset' 0

    rotateOuter !tmp !rotateOffset i
        | i >= dstLen = return ()
        | otherwise   = do
            b <- peekByteOff tmp i
            rotateInner rotateOffset b 0
            let rotateOffset' = wrap (rotateOffset + 1)
            rotateOuter tmp rotateOffset' (i + 1)

    rotateInner !rotateOffset !b j
        | j >= dstLen = return ()
        | otherwise   = do
            orByteOff dst j (b .&. eq8 (fromIntegral j) rotateOffset)
            rotateInner rotateOffset b (j + 1)

-- | @segment bs offset len@ extracts the sequence of @len@ bytes starting at
-- position @offset@ from the input bytearray @bs@.  Execution time is linear
-- with the input size and quadratic with the output size, but the code path
-- does not depend upon @offset@.
segment :: (ByteArrayAccess bin, ByteArray bout) => bin -> Int -> Int -> bout
segment bs offset len =
    B.allocAndFreeze len $ \dst ->
        B.withByteArray bs $ \src ->
            copyOffset src (B.length bs) offset dst len

-- | Verify that the given bytearray is correctly padded, with SSL conventions:
--
-- * The bytearray length must be large enough to hold all padding bytes plus an
--   additional @macSize@.
--
-- * The padding content can be arbitrary but the length must be minimal, i.e.
--   less than the specified @blockSize@.
--
-- When the bytearray is not large enough to hold @macSize@ bytes for any
-- padding length, the function returns @Nothing@.
--
-- Otherwise the function returns the validity status of the padding, and a
-- position in the bytearray where the padding starts.  When the padding is not
-- correctly formatted or not does allow to hold @macSize@ bytes, an arbitrary
-- position is returned.  The caller is supposed to execute normal integrity
-- checks based on this position before failing.  This prevents Vaudenay-style
-- attacks.
ssl :: ByteArrayAccess ba => Int -> ba -> Int -> Maybe (Bool, Int)
ssl blockSize bs macSize
    | len <= macSize = Nothing
    | otherwise      = unsafeDoIO $ B.withByteArray bs $ \p -> do
        finalByte <- peekByteOff p (len - 1) :: IO Word8
        let paddingLength = fromIntegral finalByte
            t1 = fromIntegral len - (paddingLength + 1) - fromIntegral macSize
                 -- (1) macSize + paddingLength + 1 <= len
            t2 = fromIntegral blockSize - (paddingLength + 1)
                 -- (2) paddingLength + 1 <= blockSize
            bad = msb t1 .|. msb t2
            !pos   = len - 1 - fromIntegral (paddingLength .&. isZero bad)
            !valid = bad == 0
        return $ Just (valid, pos)
  where len = B.length bs

-- | Verify that the given bytearray is correctly padded, with TLS conventions:
--
-- * The bytearray length must be large enough to hold all padding bytes plus an
--   additional @macSize@.
--
-- * The padding bytes are all equal, but the length does not need to be minimal
--   with respect to a block size.
--
-- When the bytearray is not large enough to hold @macSize@ bytes for any
-- padding length, the function returns @Nothing@.
--
-- Otherwise the function returns the validity status of the padding, and a
-- position in the bytearray where the padding starts.  When the padding is not
-- correctly formatted or not does allow to hold @macSize@ bytes, an arbitrary
-- position is returned.  The caller is supposed to execute normal integrity
-- checks based on this position before failing.  This prevents Vaudenay-style
-- attacks.
tls :: ByteArrayAccess ba => ba -> Int -> Maybe (Bool, Int)
tls bs macSize
    | len <= macSize = Nothing
    | otherwise      = unsafeDoIO $ B.withByteArray bs $ \p -> do
        finalByte <- peekByteOff p (len - 1) :: IO Word8
        let paddingLength = fromIntegral finalByte
            t1 = fromIntegral len - (paddingLength + 1) - fromIntegral macSize
                 -- (1) macSize + paddingLength + 1 <= len
            bad = msb t1
            toCheck = min 255 (len - 1)  -- not secret
        loop p paddingLength bad toCheck
  where
    len = B.length bs

    loop !p !paddingLength !bad i
        | i == 0    = finish paddingLength bad  -- reached finalByte
        | otherwise = do
            let t = paddingLength - fromIntegral i  -- i <= paddingLength
                mask = msb (complement t)
            b <- peekByteOff p (len - 1 - i) :: IO Word8
            let delta = paddingLength `xor` fromIntegral b
                bad' = bad .|. (mask .&. delta)
            loop p paddingLength bad' (i - 1)

    finish paddingLength bad =
        let !pos = len - 1 - fromIntegral (paddingLength .&. isZero bad)
            !valid = bad == 0
         in return $ Just (valid, pos)
