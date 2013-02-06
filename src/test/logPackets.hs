import Network.Firewall.NetfilerQueue.NetfilerQueue
import System.Endian

logPacket = putStrLn "Received a packet!" >> return 0

loggerCallback nfqHandle = \packetData nfDataHandle
