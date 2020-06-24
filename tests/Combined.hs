{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE StandaloneDeriving #-}
module Combined
    ( tests
    ) where

import Crypto.Hash
import qualified Crypto.CBC as CBC

import Data.ByteArray (constEq, convert)
import qualified Data.ByteString as B
import Imports

-- Example showing how to use the individual primitives to validate CBC-padded
-- messages.  This is simplified a little bit: instead of a complete HMAC, we
-- use only a digest of the message.  There is no real authentication but this
-- is enough to demontrate how to handle the variable padding and verify some
-- integrity based on the message hash.

data HashAlg = forall alg . (Show alg, HashAlgorithmPrefix alg) => HashAlg alg

deriving instance Show HashAlg

instance Arbitrary HashAlg where
    arbitrary = elements
        [ HashAlg MD5, HashAlg SHA1, HashAlg SHA224
        , HashAlg SHA256, HashAlg SHA384, HashAlg SHA512
        ]

(&&!) :: Bool -> Bool -> Bool
True  &&! True  = True
True  &&! False = False
False &&! True  = False
False &&! False = False

generatePadded :: HashAlgorithm a => a -> ByteString -> Int -> ByteString
generatePadded alg bs size =
    B.concat [ bs, digest, B.replicate (fromIntegral b) b, B.singleton b ]
  where
    digest = convert (hashWith alg bs)
    b = fromIntegral size

sslValidate :: HashAlgorithmPrefix a => a -> Int -> ByteString -> Maybe ByteString
sslValidate alg blockSize bs =
    CBC.ssl blockSize bs digestSize >>= inner alg bs digestSize
  where digestSize = hashDigestSize alg

tlsValidate :: HashAlgorithmPrefix a => a -> ByteString -> Maybe ByteString
tlsValidate alg bs = CBC.tls bs digestSize >>= inner alg bs digestSize
  where digestSize = hashDigestSize alg

inner :: HashAlgorithmPrefix a => a -> ByteString -> Int -> (Bool, Int) -> Maybe ByteString
inner alg bs digestSize (paddingValid, paddingP) =
    let (begin, end) = B.splitAt (B.length bs - 256 - digestSize) bs
        digestP = paddingP - digestSize
        endLen = digestP - B.length begin
        computed = hashCT alg begin end endLen
        extracted = CBC.segment end endLen digestSize :: ByteString
        digestValid = computed `constEq` extracted
     in guard (digestValid &&! paddingValid) >> return (B.take digestP bs)

hashCT :: HashAlgorithmPrefix a => a -> ByteString -> ByteString -> Int -> Digest a
hashCT alg begin = hashFinalizePrefix (hashUpdate (hashInitWith alg) begin)

tests :: TestTree
tests = testGroup "combined"
    [ testProperty "ssl" $ \(HashAlg alg) (ArbitraryBS0_2901 bs) -> do
        blockSize <- choose (1, 256)
        combined <- generatePadded alg bs <$> choose (0, blockSize - 1)
        let result = sslValidate alg blockSize combined
        return (Just bs `propertyEq` result)
    , testProperty "tls" $ \(HashAlg alg) (ArbitraryBS0_2901 bs) -> do
        combined <- generatePadded alg bs <$> choose (0, 255)
        let result = tlsValidate alg combined
        return (Just bs `propertyEq` result)
    ]
