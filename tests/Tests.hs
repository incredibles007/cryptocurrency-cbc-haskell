module Main where

import Imports

import qualified Hash
import qualified CBC
import qualified Combined

tests = testGroup "crypto-cbc"
    [ Hash.tests
    , CBC.tests
    , Combined.tests
    ]

main = defaultMain tests
