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
    ) where

import           Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
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
