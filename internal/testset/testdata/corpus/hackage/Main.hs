-- Minimal Haskell program that depends on one real Hackage package (text).
-- Resolved through the proxy when it is configured as a cabal remote-repo.
module Main (main) where

import qualified Data.Text as T
import qualified Data.Text.IO as TIO

main :: IO ()
main = TIO.putStrLn (T.pack "hello from a pull-through-proxied build")
