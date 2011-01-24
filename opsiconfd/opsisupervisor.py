"""
   = = = = = = = = = = = = = = = = = = = = = = =
   =   opsi supervision daemon                 =
   = = = = = = = = = = = = = = = = = = = = = = =
   
   opsiconfd is part of the desktop management solution opsi
   (open pc server integration) http://www.opsi.org
   
   Copyright (C) 2010 uib GmbH
   
   http://www.uib.de/
   
   All rights reserved.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
   
   @copyright:	uib GmbH <info@uib.de>
   @author: Christian Kampka <c.kampka@uib.de>
   @license: GNU General Public License version 2
"""


import os, pwd, signal,sys
from optparse import OptionParser

from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed, fail, DeferredList
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.error import ProcessExitedAlready
from twisted.application.service import Service, Application
from twisted.application.app import startApplication
from twisted.internet.task import LoopingCall

from OPSI.Logger import *
from OPSI.Util.amp import OpsiProcessProtocolFactory, OpsiProcessConnector
from OPSI.Util.File import IniFile
logger = Logger()

from OPSI.Service.Process import OpsiDaemon

class Opsiconfd(OpsiDaemon):
	script = 'opsiconfd'
	user = 'opsiconfd'
	socket = '/var/run/opsiconfd/opsiconfd.socket'


class Supervisor(object):

	def __init__(self, config, daemons=[Opsiconfd]):
		self._config = config
		self.daemons = []
		self.enabledDaemons = daemons
		
		self.check = LoopingCall(self.checkRunning)
		signal.signal(signal.SIGHUP, self.reload)
		
	def start(self):
		for daemon in self.enabledDaemons:
			try:
				logger.notice("Starting daemon %s" % daemon.script)
				d = daemon(args=["-l", self._config["logLevel"]])
				d.start()
				self.daemons.append(d)

			except Exception, e:
				logger.error("Failed to start daemon %s"% (daemon.script))
				logger.logException(e)
				raise
		self.delayedCall = reactor.callLater(5, self.check.start, 15, True)
		
	def reload(self):
		self.config.reload()
		for daemon in self.daemons:
			daemon.sendSignal(signal.SIGHUP)

	def checkRunning(self):
		dl = []
		for daemon in self.daemons:
			d = daemon.isRunning()
			d.addCallback(self.restartDaemon, daemon)

	def restartDaemon(self, isRunning, daemon):
		if not isRunning and daemon.allowRestart:
			d = daemon.stop()
			d.addCallback(lambda x: daemon.start)

	def stop(self):
		if self.delayedCall.active():
			self.delayedCall.cancel()		# workaround: process is killed before it's even really started
		if self.check.running:
			self.check.stop()

		l = []
		for daemon in self.daemons:
			daemon.allowRestart = False
			l.append(daemon.stop())
		return DeferredList(l)


def daemonize():
	# Fork to allow the shell to return and to call setsid
	try:
		pid = os.fork()
		if (pid > 0):
			# Parent exits
			sys.exit(0)
	except OSError, e:
		raise Exception(u"First fork failed: %e" % e)
	
	# Do not hinder umounts
	os.chdir("/")
	# Create a new session
	os.setsid()
	
	# Fork a second time to not remain session leader
	try:
		pid = os.fork()
		if (pid > 0):
			sys.exit(0)
	except OSError, e:
		raise Exception(u"Second fork failed: %e" % e)
	
	logger.setConsoleLevel(LOG_NONE)
	
	# Close standard output and standard error.
	os.close(0)
	os.close(1)
	os.close(2)
	
	# Open standard input (0)
	if (hasattr(os, "devnull")):
		os.open(os.devnull, os.O_RDWR)
	else:
		os.open("/dev/null", os.O_RDWR)
	
	# Duplicate standard input to standard output and standard error.
	os.dup2(0, 1)
	os.dup2(0, 2)
	sys.stdout = logger.getStdout()
	sys.stderr = logger.getStderr()
	
class SupervisionService(Service):
	
	def __init__(self, config):
		self.config = config
		
		logger.setConsoleLevel(config['logLevel'])
		logger.setFileLevel(config['logLevel'])
		
		self._supervisor = Supervisor(config=config)
		self.exitCode = 0
		
		
	def startService(self):
		Service.startService(self)
		try:
			if self.config["daemonize"]:
				daemonize()
				if self._config.pid_file:
					stream = open(self._config.pid_file, "w")
					stream.write(str(os.getpid()))
					stream.close()
			logger.debug2("Starting supervisor.")
		except Exception, e:
			logger.critical(u"Error starting opsi supervision service: %s" %e)
			self.exitCode = 1
			reactor.crash()

		self._supervisor.start()
	def stopService(self):
		Service.stopService(self)
		signal.signal(signal.SIGINT, signal.SIG_IGN)
		
		
		done = self._supervisor.stop()
		done.addBoth(lambda r: self._remove_pid())
		return done

	def _remove_pid(self):
		pid_file = self.config["pid_file"]
		if pid_file is not None and os.access(pid_file, os.W_OK):
			stream = open(pid_file)
			pid = stream.read()
			stream.close()
			if pid == str(os.getpid()):
				os.unlink(pid_file)
				
def main(args = sys.argv):
	logger.setConsoleLevel(LOG_WARNING)
	logger.setConsoleColor(True)

	opt = OptionParser()
	opt.add_option("-D", "--daemonize", dest="daemonize", action="store_true", 
			default=False, help="Causes the server to operate as a daemon")
	opt.add_option("--pid-file", dest="pid_file", metavar="FILE")
	opt.add_option("-l", "--log-level", help="Set log level (default: 4)", 
			type="int", default=4, action="store", dest="logLevel")
	config = vars(opt.parse_args(args)[0])

	application = Application("opsi-supervisor")
	service = SupervisionService(config=config)
	service.setServiceParent(application)
	
	reactor.callLater(0, startApplication, application, False)
	reactor.run()

	return service.exitCode
	