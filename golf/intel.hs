{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as BC
import Data.Binary.Get
import Data.Bits
import Data.Word
import Data.List (sortBy, nub, foldl', maximumBy, group, sort)
import Data.Ord (comparing, Down(..))
import System.Environment (getArgs)
import Text.Printf (printf)
import Data.Char (toLower, isDigit, isHexDigit, digitToInt)
import qualified Data.Vector.Unboxed as U
import Data.Maybe (fromMaybe)

flags :: [String]
flags = ["vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
         "compromised","datacenter","cdn","anycast","crawler","bot","cloud",
         "private_relay","anonymizer","mobile","isp","government"]

sev :: [Double]
sev = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0]

levels :: [(Double, String)]
levels = [(80,"critical"),(60,"high"),(35,"medium"),(15,"low")]

data DB = DB
  { v4Starts :: [Integer]
  , v4Ends   :: [Integer]
  , v4Vals   :: [Int]
  , v4Max    :: [Integer]
  , v6Starts :: [Integer]
  , v6Ends   :: [Integer]
  , v6Vals   :: [Int]
  , v6Max    :: [Integer]
  , values   :: [(Word32, Word32, Word32, Word32)]
  , strings  :: [String]
  , weights  :: [Double]
  }

getU32 :: Get Word32
getU32 = getWord32le

getU64 :: Get Word64
getU64 = getWord64le

getU16 :: Get Word16
getU16 = getWord16le

readNAt :: BS.ByteString -> Int -> Int -> Get a -> [a]
readNAt bs off n g
  | n <= 0 = []
  | otherwise = runGet (replicateM n g) (BL.fromStrict (BS.drop off bs))
  where replicateM k act = sequence (replicate k act)

slice :: BS.ByteString -> Int -> Int -> BS.ByteString
slice bs off len = BS.take len (BS.drop off bs)

load :: FilePath -> IO DB
load path = do
  d <- BS.readFile path
  let hdr = runGet getHeader (BL.fromStrict d)
      (ver, cn, ln, v6n, valn, strn, offs) = hdr
  if ver /= 6 then error ("unsupported version " ++ show ver) else return ()
  let [oBucket,oStartsLo,oLens,oVals,oLstarts,oLends,oLvals,
       oV6s,oV6e,oV6v,oVt,oSi,oSd,oSl] = offs
      bucket   = readNAt d oBucket 65537 getU32
      startsLo = readNAt d oStartsLo cn getU16
      lens     = readNAt d oLens cn getU16
      svals    = readNAt d oVals cn getU16
      lstarts  = readNAt d oLstarts ln getU32
      lends    = readNAt d oLends ln getU32
      lvals    = readNAt d oLvals ln getU16
      v6sRaw   = readNAt d oV6s (v6n*2) getU64
      v6eRaw   = readNAt d oV6e (v6n*2) getU64
      v6vs     = readNAt d oV6v v6n getU16
      vts      = readNAt d oVt (valn*4) getU32
      sis      = readNAt d oSi (strn*2) getU32
      blob     = slice d oSd oSl
      bid = expandBucket bucket
      smallStarts = zipWith (\b s -> (fromIntegral b `shiftL` 16) .|. fromIntegral s) bid startsLo
      smallEnds   = zipWith (+) smallStarts (map fromIntegral lens)
      smallVals   = map fromIntegral svals :: [Int]
      largeStarts = map fromIntegral lstarts :: [Integer]
      largeEnds   = map fromIntegral lends :: [Integer]
      largeVals   = map fromIntegral lvals :: [Int]
      v4Combined = sortBy (comparing (\(s,_,_) -> s))
                   (zip3 (map fromIntegral smallStarts :: [Integer])
                         (map fromIntegral smallEnds   :: [Integer]) smallVals
                    ++ zip3 largeStarts largeEnds largeVals)
      v4s = map (\(a,_,_) -> a) v4Combined
      v4e = map (\(_,b,_) -> b) v4Combined
      v4v = map (\(_,_,c) -> c) v4Combined
      v4m = runMax v4e
      v6Pairs = pairUp v6sRaw
      v6EPairs = pairUp v6eRaw
      v6sList = map (\(l,h) -> (fromIntegral h `shiftL` 64) .|. fromIntegral l) v6Pairs :: [Integer]
      v6eList = map (\(l,h) -> (fromIntegral h `shiftL` 64) .|. fromIntegral l) v6EPairs :: [Integer]
      v6vList = map fromIntegral v6vs :: [Int]
      v6m = runMax v6eList
      vt4 = chunks4 vts
      siPairs = pairUp32 sis
      strs = [BC.unpack (slice blob (fromIntegral p) (fromIntegral l)) | (p,l) <- siPairs]
      ws = computeWeights vt4 v4v
  return $ DB v4s v4e v4v v4m v6sList v6eList v6vList v6m vt4 strs ws

getHeader :: Get (Word32, Int, Int, Int, Int, Int, [Int])
getHeader = do
  ver <- getU32
  _   <- getU32
  cn  <- getU64
  ln  <- getU64
  v6n <- getU64
  valn<- getU64
  strn<- getU64
  rest <- mapM (const getU64) [1..14::Int]
  return (ver, fromIntegral cn, fromIntegral ln, fromIntegral v6n,
          fromIntegral valn, fromIntegral strn, map fromIntegral rest)

expandBucket :: [Word32] -> [Int]
expandBucket xs = concat [replicate (fromIntegral (b - a)) i
                         | (i, (a,b)) <- zip [0..] (zip xs (tail xs))]

runMax :: Ord a => [a] -> [a]
runMax [] = []
runMax (x:xs) = scanl max x xs

pairUp :: [Word64] -> [(Word64, Word64)]
pairUp (a:b:rest) = (a,b) : pairUp rest
pairUp _ = []

pairUp32 :: [Word32] -> [(Word32, Word32)]
pairUp32 (a:b:rest) = (a,b) : pairUp32 rest
pairUp32 _ = []

chunks4 :: [Word32] -> [(Word32, Word32, Word32, Word32)]
chunks4 (a:b:c:d:rest) = (a,b,c,d) : chunks4 rest
chunks4 _ = []

computeWeights :: [(Word32,Word32,Word32,Word32)] -> [Int] -> [Double]
computeWeights vt v4v
  | null v4v = sev
  | otherwise =
      let bitsList = [let (b,_,_,_) = vt !! vid in b | vid <- v4v]
          tot = length v4v
          counts = [length [() | b <- bitsList, testBit b i] | i <- [0..19]]
      in [s * (1 + logBase 2 (fromIntegral tot / fromIntegral (max c 1)) / 24)
         | (s, c) <- zip sev counts]

upperBound :: Ord a => [a] -> a -> Int
upperBound xs target = go 0 (length xs)
  where
    v = U.fromList [0..]
    arr = xs
    go lo hi
      | lo >= hi = lo
      | otherwise =
          let mid = (lo + hi) `div` 2
          in if (arr !! mid) <= target then go (mid+1) hi else go lo mid

hits :: [Integer] -> [Integer] -> [Int] -> [Integer] -> Integer
     -> [(Integer, Integer, Int)]
hits starts ends vals maxs ip
  | null starts = []
  | otherwise =
      let n = length starts
          sArr = U.fromList (map fromInteger starts :: [Integer]) `seq` starts
          i0 = upperBound starts ip
      in collect (i0 - 1)
  where
    sList = starts
    eList = ends
    vList = vals
    mList = maxs
    collect i
      | i < 0 = []
      | (mList !! i) < ip = []
      | (eList !! i) >= ip =
          (sList !! i, eList !! i, vList !! i) : collect (i-1)
      | otherwise = collect (i-1)

parseIP :: String -> Maybe (Bool, Integer)
parseIP s
  | '.' `elem` s && ':' `notElem` s = fmap (\x -> (True, x)) (parseV4 s)
  | ':' `elem` s = fmap (\x -> (False, x)) (parseV6 s)
  | otherwise = Nothing

parseV4 :: String -> Maybe Integer
parseV4 s =
  let parts = splitOn '.' s
  in if length parts /= 4 then Nothing
     else do
       ns <- mapM readOctet parts
       return (foldl' (\a b -> a * 256 + b) 0 ns)
  where
    readOctet x = case reads x :: [(Integer, String)] of
      [(n,"")] | n >= 0 && n <= 255 -> Just n
      _ -> Nothing

splitOn :: Char -> String -> [String]
splitOn c s = case break (== c) s of
  (a, []) -> [a]
  (a, _:rest) -> a : splitOn c rest

parseV6 :: String -> Maybe Integer
parseV6 s = do
  let (headP, tailP) = case splitOnSeq "::" s of
        [a] -> (splitOn ':' a, [])
        [a, b] -> (if null a then [] else splitOn ':' a,
                   if null b then [] else splitOn ':' b)
        _ -> ([], [])
  if length headP + length tailP > 8 then Nothing
    else do
      let mid = replicate (8 - length headP - length tailP) "0"
          allG = headP ++ mid ++ tailP
      if length allG /= 8 then Nothing
        else do
          ns <- mapM readHex allG
          return (foldl' (\a b -> a `shiftL` 16 .|. b) 0 ns)
  where
    readHex x
      | null x || length x > 4 = Nothing
      | all isHexDigit x = Just (foldl' (\a c -> a*16 + fromIntegral (digitToInt c)) 0 x)
      | otherwise = Nothing

splitOnSeq :: String -> String -> [String]
splitOnSeq sep s = go s
  where
    n = length sep
    go [] = [""]
    go str
      | take n str == sep = "" : go (drop n str)
      | otherwise = case go (tail str) of
          (h:t) -> (head str : h) : t
          [] -> [[head str]]

formatV4 :: Integer -> String
formatV4 ip =
  let a = (ip `shiftR` 24) .&. 0xff
      b = (ip `shiftR` 16) .&. 0xff
      c = (ip `shiftR`  8) .&. 0xff
      d =  ip              .&. 0xff
  in show a ++ "." ++ show b ++ "." ++ show c ++ "." ++ show d

formatV6 :: Integer -> String
formatV6 ip =
  let groups = [fromInteger ((ip `shiftR` (16 * (7 - i))) .&. 0xffff) :: Int
               | i <- [0..7]]
      hex = map (printf "%x") groups :: [String]
      (bestStart, bestLen) = longestZeroRun groups
  in if bestLen >= 2
     then let before = take bestStart hex
              after  = drop (bestStart + bestLen) hex
              bs = if null before then "" else foldl1 (\a b -> a ++ ":" ++ b) before
              as = if null after then "" else foldl1 (\a b -> a ++ ":" ++ b) after
          in bs ++ "::" ++ as
     else foldl1 (\a b -> a ++ ":" ++ b) hex

longestZeroRun :: [Int] -> (Int, Int)
longestZeroRun xs = go 0 0 0 0 (-1) xs
  where
    go _ _ bs bl _ [] = (bs, bl)
    go i cs cl bs bl (x:rest)
      | x == 0 =
          let cl' = if cl == 0 then 1 else cl + 1
              cs' = if cl == 0 then i else cs
          in if cl' > bl then go (i+1) cs' cl' cs' cl' rest
             else go (i+1) cs' cl' bs bl rest
      | otherwise = go (i+1) 0 0 bs bl rest

round1 :: Double -> Double
round1 x = fromIntegral (round (x * 10) :: Integer) / 10

num :: Double -> String
num v
  | v == fromIntegral (round v :: Integer) = show (round v :: Integer) ++ ".0"
  | otherwise = printf "%.1f" v

jsonStr :: String -> String
jsonStr s = "\"" ++ concatMap esc s ++ "\""
  where
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c = [c]

jsonList :: [String] -> String
jsonList xs = "[" ++ intercalate ", " xs ++ "]"

intercalate :: String -> [String] -> String
intercalate _ [] = ""
intercalate _ [x] = x
intercalate sep (x:xs) = x ++ sep ++ intercalate sep xs

data Match = Match
  { mSource :: String
  , mProv   :: String
  , mRange  :: String
  , mFlags  :: [String]
  , mWeight :: Double
  }

lookupIP :: DB -> String -> String
lookupIP db ipStr =
  case parseIP ipStr of
    Nothing -> "{\"ip\": " ++ jsonStr ipStr ++ ", \"error\": \"invalid ip\"}"
    Just (isV4, ip) ->
      let hs = if isV4
                 then hits (v4Starts db) (v4Ends db) (v4Vals db) (v4Max db) ip
                 else hits (v6Starts db) (v6Ends db) (v6Vals db) (v6Max db) ip
          fmtRange s e = if isV4
                           then formatV4 s ++ "-" ++ formatV4 e
                           else formatV6 s ++ "-" ++ formatV6 e
          mkMatch (s, e, vid) =
            let (b, prov, src, _) = values db !! vid
                fl = [flags !! i | i <- [0..19], testBit b i]
                w = round1 (maximum (0 : [weights db !! i
                                         | (i,f) <- zip [0..] flags, f `elem` fl]))
            in Match (strings db !! fromIntegral src)
                     (strings db !! fromIntegral prov)
                     (fmtRange s e) fl w
          matches = sortBy (comparing (Down . mWeight)) (map mkMatch hs)
          allFlagsEnc = dedup (concatMap mFlags matches)
          ranked = sortBy (comparing (\f -> Down (weightOf db f))) allFlagsEnc
          srcSet = dedup [(mProv m, mSource m) | m <- matches]
          score = if null ranked then 0.0
                  else round1 (min 100
                       ((weightOf db (head ranked)
                         + sum (map (weightOf db) (tail ranked)) * 0.15)
                        * (1 + 0.08 * logBase 2 (fromIntegral (length srcSet + 1)))))
          verdict
            | null matches = "clean"
            | otherwise = fromMaybe "minimal"
                          (lookup True [(score >= t, n) | (t,n) <- levels])
          provRaw = dedup [mProv m | m <- matches, not (null (mProv m))]
          providers = if any (\p -> map toLower p == "tor") provRaw
                      then "Tor" : [p | p <- provRaw, map toLower p /= "tor"]
                      else provRaw
          topProv = if null providers then "" else head providers
          reasons = take 5 ranked
      in renderJSON ipStr (not (null matches)) verdict score
                    (length matches) (length srcSet) topProv
                    providers allFlagsEnc reasons matches

weightOf :: DB -> String -> Double
weightOf db f = case lookup f (zip flags (weights db)) of
  Just w -> w
  Nothing -> 0

dedup :: Eq a => [a] -> [a]
dedup [] = []
dedup (x:xs) = x : dedup (filter (/= x) xs)

renderJSON :: String -> Bool -> String -> Double -> Int -> Int -> String
           -> [String] -> [String] -> [String] -> [Match] -> String
renderJSON ip found verdict score dets srcs topProv provs allF reasons matches =
  "{\n" ++ intercalate ",\n"
    [ "  \"ip\": " ++ jsonStr ip
    , "  \"found\": " ++ (if found then "true" else "false")
    , "  \"verdict\": " ++ jsonStr verdict
    , "  \"score\": " ++ num score
    , "  \"detections\": " ++ show dets
    , "  \"sources\": " ++ show srcs
    , "  \"top_provider\": " ++ jsonStr topProv
    , "  \"providers\": " ++ jsonList (map jsonStr provs)
    , "  \"flags\": " ++ jsonList (map jsonStr allF)
    , "  \"reasons\": " ++ jsonList (map jsonStr reasons)
    , "  \"matches\": " ++ renderMatches matches
    ] ++ "\n}"

renderMatches :: [Match] -> String
renderMatches [] = "[]"
renderMatches ms = "[\n" ++ intercalate ",\n" (map renderMatch ms) ++ "\n  ]"

renderMatch :: Match -> String
renderMatch m =
  "    {\"source\": " ++ jsonStr (mSource m)
  ++ ", \"provider\": " ++ jsonStr (mProv m)
  ++ ", \"range\": " ++ jsonStr (mRange m)
  ++ ", \"flags\": " ++ jsonList (map jsonStr (mFlags m))
  ++ ", \"weight\": " ++ num (mWeight m) ++ "}"

main :: IO ()
main = do
  args <- getArgs
  let ip = case args of { (a:_) -> a; _ -> "8.8.8.8" }
  db <- load "../intel.bin"
  putStrLn (lookupIP db ip)
