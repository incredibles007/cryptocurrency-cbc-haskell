module CBC
    ( tests
    ) where

import Crypto.CBC

import qualified Data.ByteString as B
import Imports

prop_segment :: ArbitraryBS0_2901 -> NonNegative Int -> Int0_131 -> Bool
prop_segment (ArbitraryBS0_2901 bs) (NonNegative offset) (Int0_131 len) =
    let result = B.take len (B.drop offset bs)
        extra  = B.replicate (len - B.length result) 0
     in segment bs offset len == result `B.append` extra

tests :: TestTree
tests = testGroup "cbc"
    [ testProperty "segment" prop_segment
    ]
