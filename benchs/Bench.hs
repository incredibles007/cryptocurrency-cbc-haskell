module Main where

import Criterion.Main

import qualified Crypto.CBC as CBC
import           Crypto.Hash

import Control.Monad

import Data.ByteArray (constEq, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

-- Compares the original implementation in @tls@ with constant-time handling of
-- CBC padding.  The code is simplified a little bit: instead of a complete
-- HMAC, we use only a digest of the message.  There is no real authentication
-- but the difference with a complete implementation is a constant factor.

totalLen :: Int
totalLen = 16384

hashAlg :: SHA256
hashAlg = SHA256

digestSize :: Int
digestSize = hashDigestSize hashAlg

data CipherData = CipherData
    { cipherDataContent :: ByteString
    , cipherDataMAC     :: Maybe ByteString
    , cipherDataPadding :: Maybe ByteString
    } deriving (Show,Eq)

(&&!) :: Bool -> Bool -> Bool
True  &&! True  = True
True  &&! False = False
False &&! True  = False
False &&! False = False

partition3 :: ByteString -> (Int,Int,Int) -> Maybe (ByteString, ByteString, ByteString)
partition3 bytes (d1,d2,d3)
    | any (< 0) l             = Nothing
    | sum l /= B.length bytes = Nothing
    | otherwise               = Just (p1,p2,p3)
        where l        = [d1,d2,d3]
              (p1, r1) = B.splitAt d1 bytes
              (p2, r2) = B.splitAt d2 r1
              (p3, _)  = B.splitAt d3 r2

getCipherData :: CipherData -> Maybe ByteString
getCipherData cdata = do
    let macValid =
            case cipherDataMAC cdata of
                Nothing     -> True
                Just digest ->
                    let expected_digest = hashWith hashAlg $ cipherDataContent cdata
                     in expected_digest `constEq` digest

    let paddingValid =
            case cipherDataPadding cdata of
                Nothing  -> True
                Just pad ->
                    let b = B.length pad - 1
                     in B.replicate (B.length pad) (fromIntegral b) `constEq` pad

    guard (macValid &&! paddingValid)
    return $ cipherDataContent cdata

generatePadded :: Bool -> Bool -> Int -> ByteString
generatePadded invalidPadding invalidDigest size =
    B.concat [ bs, digest, B.replicate (fromIntegral b) b, B.singleton c ]
  where
    bs     = B.replicate (totalLen - size) 0x11
    b      = fromIntegral size

    digest | invalidDigest = B.replicate digestSize 0x22
           | otherwise     = convert (hashWith hashAlg bs)

    c | invalidPadding = if b >= 0x80 then b - 1 else b + 1
      | otherwise = b

benchOrig :: Bool -> Bool -> Int -> Benchmark
benchOrig invalidPadding invalidDigest padLen = bench (show padLen) $
    nf run (generatePadded invalidPadding invalidDigest padLen)
  where
    get3i  = partition3
    run bs = do
            let paddinglength = fromIntegral (B.last bs) + 1
            let contentlen = B.length bs - paddinglength - digestSize
            (content, mac, padding) <- get3i bs (contentlen, digestSize, paddinglength)
            getCipherData CipherData
                    { cipherDataContent = content
                    , cipherDataMAC     = Just mac
                    , cipherDataPadding = Just padding
                    }

benchCT :: Bool -> Bool -> Int -> Benchmark
benchCT invalidPadding invalidDigest padLen = bench (show padLen) $
    nf run (generatePadded invalidPadding invalidDigest padLen)
  where
    run bs = CBC.tls bs digestSize >>= \(paddingValid, paddingP) ->
        let (begin, endmac) = B.splitAt (B.length bs - 256 - digestSize) bs
            digestP = paddingP - digestSize
            endLen = digestP - B.length begin
            end = B.take 255 endmac  -- digest and last padding byte never needed
            computed = hashCT hashAlg begin end endLen
            extracted = CBC.segment endmac endLen digestSize :: ByteString
            digestValid = computed `constEq` extracted
         in guard (digestValid &&! paddingValid) >> return (B.take digestP bs)

hashCT :: HashAlgorithmPrefix a => a -> ByteString -> ByteString -> Int -> Digest a
hashCT alg begin = hashFinalizePrefix (hashUpdate (hashInitWith alg) begin)

main :: IO ()
main = defaultMain
    [ bgroup "CBC"
        [ bgroup "original"
            [ bgroup "valid" $ map (benchOrig False False) sizes
            , bgroup "invalid-padding" $ map (benchOrig True False) sizes
            , bgroup "invalid-digest" $ map (benchOrig False True) sizes
            ]
        , bgroup "constant-time"
            [ bgroup "valid" $ map (benchCT False False) sizes
            , bgroup "invalid-padding" $ map (benchCT True False) sizes
            , bgroup "invalid-digest" $ map (benchCT False True) sizes
            ]
        ]
    ]
  where sizes = [0, 15, 31, 63, 127, 191, 255]
