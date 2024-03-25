import io
import asyncio
import argparse
import ctypes
import struct
import sys
from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from aardwolf.protocol.T125.extendedinfopacket import PERF
from aardwolf.commons.iosettings import RDPIOSettings

async def amain():
	# Parse the arguments
	parser = argparse.ArgumentParser(description="RDP Connection Parameters")
	parser.add_argument("ip_address", help="IP address of the remote computer")
	parser.add_argument("username", help="Username")
	parser.add_argument("password", help="Password")
	parser.add_argument("width", type=int, help="Screen width")
	parser.add_argument("height", type=int, help="Screen height")
	args = parser.parse_args()
	
	# Generate the RDP connection URL string
	rdp_url = f"rdp+ntlm-password://{args.username}:{args.password}@{args.ip_address}"
	
	# Establish a headless RDP connection
	iosettings = RDPIOSettings()
	factory = RDPConnectionFactory.from_url(rdp_url, iosettings)
	iosettings.channels = []
	iosettings.video_width = args.width
	iosettings.video_height = args.height
	iosettings.video_bpp_min = 24
	iosettings.video_bpp_max = 32
	iosettings.video_out_format = VIDEO_FORMAT.PIL
	iosettings.clipboard_use_pyperclip = False
	iosettings.performance_flags = PERF.ENABLE_FONT_SMOOTHING | PERF.ENABLE_DESKTOP_COMPOSITION
	connection = None
	pipe_connected = False
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