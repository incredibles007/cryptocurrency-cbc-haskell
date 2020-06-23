module CBC
    ( tests
    ) where

import Crypto.CBC

import Data.Bits
import qualified Data.ByteString as B
import Data.Maybe
import Imports

prop_segment :: ArbitraryBS0_2901 -> Int -> Int0_131 -> Bool
prop_segment (ArbitraryBS0_2901 bs) offset (Int0_131 len)
    | offset < 0 = B.replicate len 0 `propertyEq` segment bs offset len
    | otherwise  =
        let result = B.take len (B.drop offset bs)
            extra  = B.replicate (len - B.length result) 0
         in (result `B.append` extra) `propertyEq` segment bs offset len

arbitraryPaddingSSL :: Int -> Gen ByteString
arbitraryPaddingSSL size = do
    randomPart <- B.pack <$> vectorOf size arbitraryBoundedRandom
    return (randomPart `B.snoc` fromIntegral size)

arbitraryPaddingTLS :: Gen ByteString
arbitraryPaddingTLS = arbitraryBoundedRandom >>= \b ->
    return (B.replicate (fromIntegral b) b `B.snoc` b)

alter :: ByteString -> Gen ByteString
alter bs
    | len < 2   = return bs
    | otherwise = do
        pos <- choose (0, len - 2)  -- not the final byte
        bit <- choose (0, 7)
        let (prefix, (original:suffix)) = splitAt pos (B.unpack bs)
            altered = original `xor` shiftL 1 bit
        return $! B.pack (prefix ++ (altered:suffix))
  where len = B.length bs

tests :: TestTree
tests = testGroup "cbc"
    [ testProperty "segment" prop_segment
    , testGroup "ssl"
        [ testProperty "valid" $ \(ArbitraryBS0_2901 bs) (ArbitraryBS0_2901 mac) -> do
            let len = B.length bs + B.length mac
            blockSize <- choose (1, 128)
            let size = negate len `mod` blockSize
            padding <- arbitraryPaddingSSL size
            let result = ssl blockSize (B.concat [bs, mac, padding]) (B.length mac)
            return $ Just (True, len) `propertyEq` result
        , testProperty "altered" $ \(ArbitraryBS0_2901 bs) (ArbitraryBS0_2901 mac) -> do
            let len = B.length bs + B.length mac
            blockSize <- choose (1, 256)
            let size = negate len `mod` blockSize
            padding <- arbitraryPaddingSSL size >>= alter
            let result = ssl blockSize (B.concat [bs, mac, padding]) (B.length mac)
            return $ Just (True, len) `propertyEq` result
        , testProperty "not-minimal" $ \(ArbitraryBS0_2901 bs) (ArbitraryBS0_2901 mac) -> do
            let len = B.length bs + B.length mac
            blockSize <- choose (1, 128)
            let size = (negate len `mod` blockSize) + blockSize
            padding <- arbitraryPaddingSSL size
            let result = ssl blockSize (B.concat [bs, mac, padding]) (B.length mac)
                expected = Just (False, len + B.length padding - 1)
            return $ expected `propertyEq` result
        , testProperty "too-small" $ \(NonNegative n) (NonNegative m) -> do
            blockSize <- choose (1, 256)
            size <- choose (0, blockSize - 1)
            padding <- arbitraryPaddingSSL size
            let result = ssl blockSize (B.drop n padding) m
                expected | n + m >= B.length padding = Nothing
                         | n + m > 0 = Just (False, B.length padding - 1 - n)
                         | otherwise = Just (True, 0)
            return $ expected `propertyEq` result
        ]
    , testGroup "tls"
        [ testProperty "valid" $ \(ArbitraryBS0_2901 bs) (ArbitraryBS0_2901 mac) -> do
            let len = B.length bs + B.length mac
            padding <- arbitraryPaddingTLS
            let result = tls (B.concat [bs, mac, padding]) (B.length mac)
            return $ Just (True, len) `propertyEq` result
        , testProperty "altered" $ \(ArbitraryBS0_2901 bs) (ArbitraryBS0_2901 mac) -> do
            let len = B.length bs + B.length mac
            padding <- arbitraryPaddingTLS >>= alter
            let result = tls (B.concat [bs, mac, padding]) (B.length mac)
                expLen = len + B.length padding - 1
            return $ Just (B.length padding < 2, expLen) `propertyEq` result
        , testProperty "too-small" $ \(NonNegative n) (NonNegative m) -> do
            padding <- arbitraryPaddingTLS
            let result = tls (B.drop n padding) m
                expected | n + m >= B.length padding = Nothing
                         | n + m > 0 = Just (False, B.length padding - 1 - n)
                         | otherwise = Just (True, 0)
            return $ expected `propertyEq` result
        ]
    ]
