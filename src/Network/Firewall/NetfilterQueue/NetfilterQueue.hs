{-# LANGUAGE ForeignFunctionInterface #-}
module NetfilterQueue where
import Foreign.C
import Foreign.C.Types (CInt(..))
import Foreign.Ptr

data NfqH = NfqH
type NetfilterHandle = Ptr NfqH

data NfqQH = NfqQH
type NetfilterQueueHandle = Ptr NfqQH

data NfGenMsg = NfGenMsg
type NetfilterPacketData = Ptr NfGenMsg

data NfData = NfData
type NetfilterDataHandle = Ptr NfData

type NetfilterUserData = Ptr ()

type NfqCB = (NetfilterQueueHandle -> NetfilterPacketData -> NetfilterDataHandle -> NetfilterUserData -> IO CInt)
type NetfilterCallback = FunPtr NfqCB

type NetfilterPacketBuffer = CString

-- data NfqCallback = 

-- Library Setup
foreign import ccall "nfq_open"      nfq_open      :: IO NetfilterHandle
foreign import ccall "nfq_close"     nfq_close     :: NetfilterHandle -> IO CInt
foreign import ccall "nfq_bind_pf"   nfq_bind_pf   :: NetfilterHandle -> CShort -> IO CInt
foreign import ccall "nfq_unbind_pf" nfq_unbind_pf :: NetfilterHandle -> CShort -> IO CInt

-- Queue Handling
foreign import ccall "nfq_fd" nfq_fd :: NetfilterHandle -> IO CInt
foreign import ccall "nfq_create_queue" nfq_create_queue :: NetfilterHandle -> 
                                                            CShort -> 
                                                            NetfilterCallback -> 
                                                            NetfilterUserData -> 
                                                            IO NetfilterQueueHandle
foreign import ccall "nfq_destroy_queue" nfq_destroy_queue :: NetfilterQueueHandle -> IO CInt
foreign import ccall "nfq_handle_packet" nfq_handle_packet :: NetfilterQueueHandle -> NetfilterPacketBuffer -> CInt -> IO CInt
foreign import ccall "nfq_set_mode"      nfq_set_mode      :: 
