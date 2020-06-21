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
     in (result `B.append` extra) `propertyEq` segment bs offset len

tests :: TestTree
tests = testGroup "cbc"
    [ testProperty "segment" prop_segment
    ]
