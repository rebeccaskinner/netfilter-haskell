{-# LANGUAGE ForeignFunctionInterface #-}
module Network.Firewall.NetfilterQueue.NetfilterQueue where
import Foreign.C
import Foreign.C.Types (CInt(..))
import Foreign.Ptr
import Foreign.Storable

data NfqH = NfqH
type NetfilterHandle = Ptr NfqH

data NfqQH = NfqQH
type NetfilterQueueHandle = Ptr NfqQH

data NfGenMsg = NfGenMsg { packet_id   :: CUInt
                         , hw_protocol :: CUShort
                         , hook        :: CUChar
                         }

type NetfilterPacketData = Ptr NfGenMsg

instance Storable NfGenMsg where
    sizeOf _    = sizeOf (0 :: CUInt)   +
                  sizeOf (0 :: CUShort) + 
                  sizeOf (0 :: CUChar)
    alignment _ = sizeOf (0 :: CUInt) * (ceiling $ sizeOf (NfqQH 0 0 0))
    peek p      = do 
                    ptr1 <- peek $ ((castPtr p) :: Ptr CUInt)
                    ptr2 <- peek $ ((castPtr (plusPtr ptr1 (0 :: sizeOf CUInt)))   :: Ptr CUShort)
                    ptr3 <- peek $ ((castPtr (plusPtr ptr2 (0 :: sizeOf CUShort))) :: Ptr CUChar)
                  where
                  ntohl val = 

data NfData = NfData
type NetfilterDataHandle = Ptr NfData

data NfMsgPacketHdr = NfMsgPacketHdr
type NetfilterPacketHeader = Ptr NfMsgPacketHdr

type NetfilterUserData = Ptr ()

data NFTVal   = NFTVal
type NFTimeValue = Ptr NFTVal

type NfqCB = (NetfilterQueueHandle -> NetfilterPacketData -> NetfilterDataHandle -> NetfilterUserData -> IO CInt)
type NetfilterCallback = FunPtr NfqCB

type NetfilterPacketBuffer = CString
type NFVerdict             = CUInt
type NFPacketID            = CUInt
type NFMode                = CUChar
type NFMark                = CUInt

data NetfilterVerdict = NF_DROP
                      | NF_ACCEPT
                      | NF_STOLEN
                      | NF_QUEUE
                      | NF_REPEAT
                      | NF_STOP
                      | NF_MAX_VERDICT

data NetfilterCopyDirective = NFQNL_COPY_NONE
                            | NFQNL_COPY_META
                            | NFQNL_COPY_PACKET


netfilterCLibValue :: NetfilterVerdict -> NFVerdict
netfilterCLibValue NF_DROP        = 0 :: NFVerdict
netfilterCLibValue NF_ACCEPT      = 1 :: NFVerdict
netfilterCLibValue NF_STOLEN      = 2 :: NFVerdict
netfilterCLibValue NF_QUEUE       = 3 :: NFVerdict
netfilterCLibValue NF_REPEAT      = 4 :: NFVerdict
netfilterCLibValue NF_STOP        = 5 :: NFVerdict
netfilterCLibValue NF_MAX_VERDICT = netfilterCLibValue NF_STOP

-- Note: nfqnl_copy_mode is defined as an enum in linux_nfnetlink_queue.h
--       here we are hard-coding the integer values of the enumeration
--       constants for simplicity; this is likely to break if additional
--       modes are added later, or if other interger values are specified
--       in future versions of the library.
netfilterCopyMode :: NetfilterCopyDirective -> NFMode
netfilterCopyMode NFQNL_COPY_NONE   = 0
netfilterCopyMode NFQNL_COPY_META   = 1
netfilterCopyMode NFQNL_COPY_PACKET = 2

-- Library Setup
-- See the Netfiler C documentation for a more thourough explanation of these
-- functions, their expected inputs and outputs, and their general behavior.
-- http://netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html

-- Get a new netfiler handle
foreign import ccall unsafe "nfq_open" nfq_open ::
    IO NetfilterHandle

-- Close a netfilter handle
foreign import ccall unsafe "nfq_close" nfq_close ::
    NetfilterHandle -> -- The netfilter handle to close
    IO CInt

-- Bind a netfilter handle to an NF Queue
foreign import ccall unsafe "nfq_bind_pf" nfq_bind_pf ::
    NetfilterHandle -> -- Netfilter handle to bind
    CShort ->          -- Queue number to bind to
    IO CInt            -- Status Code

-- Unbind a netfiler handle from an NF Queue
foreign import ccall unsafe "nfq_unbind_pf" nfq_unbind_pf ::
    NetfilterHandle -> -- Netfiler handle to unbind
    CShort ->          -- Queue number to unbind
    IO CInt            -- Status Code

-- Queue Handling
-- http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html

-- Get a file descriptor associated with a netfilter handler.  This can be used
-- for Polling / Event Loops
foreign import ccall unsafe "nfq_fd" nfq_fd ::
    NetfilterHandle -> -- Netfilter Handle
    IO CInt            -- Pollable FD

-- Create a Queue Handle from the Netfiler Handle
foreign import ccall unsafe "nfq_create_queue" nfq_create_queue ::
    NetfilterHandle ->       -- The netfiler handle to create the queue handle from
    CShort ->                -- The queue number to bind to
    NetfilterCallback ->     -- The callback function to use when processing packets
    NetfilterUserData ->     -- User data passed into the callback
    IO NetfilterQueueHandle  -- The queue handle

-- Destroy a queue
foreign import ccall unsafe "nfq_destroy_queue" nfq_destroy_queue ::
    NetfilterQueueHandle -> -- The Queue handle to destroy
    IO CInt

-- Handle a packet by passing it to the registered callback function
foreign import ccall safe "nfq_handle_packet" nfq_handle_packet ::
    NetfilterQueueHandle ->  -- The handle that owns the packet
    NetfilterPacketBuffer -> -- The packet buffer
    CInt ->                  -- Packet buffer length (in bytes)
    IO CInt

-- Set the copy mode for the packets (e.g. None, Metadata only, Whole Packet)
foreign import ccall unsafe "nfq_set_mode" nfq_set_mode ::
    NetfilterQueueHandle -> -- The Queue Handle to Modify
    NFMode ->               -- The new copy mode
    CUInt ->                -- Packet size range
    IO CInt

-- Set the maximum number of packets that we will queue before the
-- kernel starts dropping packets.  This can be an important number to tune due
-- to the fact that it will affect the way various congestion control
-- algorithms tune the packet size/rate for a conversation.
foreign import ccall unsafe "nfq_set_queue_maxlen" nfq_set_queue_maxlen ::
    NetfilterQueueHandle -> -- The handle to modify
    CUInt ->                -- Maximum queue length
    IO CInt

-- Set a packet verdict
foreign import ccall unsafe "nfq_set_verdict" nfq_set_verdict ::
    NetfilterQueueHandle ->  -- Queue handle owning the packet
    NFPacketID ->            -- The packet ID for the packet (obtained from nfq_get_msg_packet_hdr)
    NFVerdict ->             -- The verdict to set
    CUInt ->                 -- Buffer Length
    NetfilterPacketBuffer -> -- Packet data buffer
    IO CInt

-- As with nfq_set_verdict, but you can also set a mark for the packet
foreign import ccall unsafe "nfq_set_verdict2" nfq_set_verdict2 ::
    NetfilterQueueHandle ->  -- The queue handle owning the packet
    NFPacketID ->            -- The packet id
    NFVerdict ->             -- Packet Verdict
    NFMark ->                -- Packet Mark
    CUInt ->                 -- Packet Buffer Length
    NetfilterPacketBuffer -> -- Packet Data Buffer
    IO CInt

-- Message Parsing Functions 
-- http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html

-- Retreive the packet header information from the packet data buffer
-- provided to your callback by the handle packet function.
foreign import ccall unsafe "nfq_get_msg_packet_hdr" nfq_get_msg_packet_hdr ::
    NetfilterDataHandle ->   -- The data handle provided to a packet handler callback
    IO NetfilterPacketHeader -- Packet header from the data handle

-- Retreive the mark (if any) that has been set on the packet.  A mark may have
-- been set in the kernel, by some iptables rule that has been processed before
-- the packet was queued, or by another application using libnetfiler_queue
-- that has already processed the packet.
foreign import ccall unsafe "nfq_get_nfmark" nfq_get_nfmark ::
    NetfilterDataHandle -> -- The data handle provided to a packet handler callback
    IO NFMark              -- The mark set for the packet

foreign import ccall unsafe "nfq_get_timestamp" nfq_get_timestamp ::
    NetfilterDataHandle -> -- Data handle provided to the packet handler
    NFTimeValue         -> -- Timeval
    IO CInt                -- return code


