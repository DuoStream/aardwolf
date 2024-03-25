import io
import asyncio
import argparse
import ctypes
import struct
import sys
from urllib.parse import quote
from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from aardwolf.commons.target import RDPTarget, RDPConnectionDialect
from aardwolf.protocol.T125.extendedinfopacket import PERF
from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.subprotocols import SubProtocolNative
from asysocks.unicomm.common.target import UniProto

async def amain():
	# Parse the arguments
	parser = argparse.ArgumentParser(description="RDP Connection Parameters")
	parser.add_argument("ip_address", help="IP address of the remote computer")
	parser.add_argument("client_name", help="Client name")
	parser.add_argument("username", help="Username")
	parser.add_argument("password", help="Password")
	parser.add_argument("keyboard_layout", type=int, help="Keyboard layout")
	parser.add_argument("width", type=int, help="Screen width")
	parser.add_argument("height", type=int, help="Screen height")
	args = parser.parse_args()

	# Establish a headless RDP connection
	iosettings = RDPIOSettings()
	iosettings.client_name = args.client_name
	iosettings.channels = []
	iosettings.keyboard_layout = args.keyboard_layout
	iosettings.video_width = args.width
	iosettings.video_height = args.height
	iosettings.video_bpp_min = 24
	iosettings.video_bpp_max = 32
	iosettings.video_out_format = VIDEO_FORMAT.PIL
	iosettings.clipboard_use_pyperclip = False
	iosettings.performance_flags = PERF.ENABLE_FONT_SMOOTHING | PERF.ENABLE_DESKTOP_COMPOSITION
	target = RDPTarget(args.ip_address, 3389, None, 5, None, None, None, UniProto.CLIENT_TCP, False, RDPConnectionDialect.RDP, None)
	credential = NTLMCredential(args.password, args.username, None, asyauthSecret.PASSWORD, SubProtocolNative())
	factory = RDPConnectionFactory(iosettings, target, credential)
	connection = None
	try:
		connection = factory.get_connection(iosettings)
		err = await connection.connect()
		if err is not None:
			if not err[0]:
				raise err[1];
			while True:
				if connection.disconnected_evt.is_set():
					break
				data = await connection.ext_out_queue.get()
	except asyncio.CancelledError:
		return
	except Exception as e:
		raise
	finally:
		if connection is not None:
			await connection.terminate()

def main():
	try:
		asyncio.run(amain())
		sys.exit(0)
	except Exception as e:
		raise e
		sys.exit(1)

if __name__ == "__main__":
	main()