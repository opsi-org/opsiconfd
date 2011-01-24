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


class OpsiDaemon(object):
	
	script = None
	user = None
	allowMultiple = False
	allowRestart = True
	connector = OpsiProcessConnector
	nextPort = None
	proto = "https"
			
	def __init__(self, config = {}, args = [], reactor=reactor):
		self._port = self.nextPort if self.nextPort is not None else int(config.setdefault("port", 4447))
		self.proto = config.setdefault("protocol", self.proto)
		self._config = config
		self._reactor = reactor
		self._connector = None
		self._env = os.environ.copy()
		self._process = None
		self._args = args
		self._checkFailures = 0
		
		if os.getuid() == 0:
			if not self.user:
				raise RuntimeError("Subclass %s must specifie a daemon user if run as root." % self.script)
			
			passwd = pwd.getpwnam(self.user)
			self._uid = passwd.pw_uid
			self._gid = passwd.pw_gid
			self._env['USER'] = self.user
			self._env['HOME'] = passwd.pw_dir
		else:
			self._uid, self._gid = None, None
	
	def getPort(self):
		port = self._port
		self.__class__.nextPort = self._port + 1
		print self.__class__.nextPort
		return port
			
	def start(self):

		self._process = SupervisionProtocol(self)
		script = self.findScript()
		args = [script]
		args.extend(self._args)
		if self.proto == "https":
			args.extend(["-P", str(self.getPort())])
		else:
			args.extend(["-p", str(self.getPort())])

		self._reactor.spawnProcess(self._process, script, args=args,
				   env=self._env, uid=self._uid, gid=self._gid)
		
	def stop(self):
		if not self._process:

			succeed(None)
		return self._process.stop()
		
	def findScript(self):
		if self.script is None:
			raise RuntimeError("Subclass %s must provide an executable script." % self.script)
		
		dirname = os.path.dirname(os.path.abspath(sys.argv[0]))
		script = os.path.join(dirname, self.script)
		if not os.path.exists(script) or not os.access(script, os.X_OK):
			raise RuntimeError("Script %s doesn't exist or is not executable." % script)
		return script

	def callRemote(self, method, *args, **kwargs):
		def disconnect(result):		
			self._connector.disconnect()
			return result
		
		def failure(failure):
			logger.error(failure.getErrorMessage())
			logger.logException(failure.getException())
			return False

		
		connection = self._connector.connect()
		connection.addCallback(lambda remote: getattr(remote, method)(*args, **kwargs))
		connection.addCallback(disconnect)
		connection.addErrback(failure)
		return connection
	
	def isRunning(self):
		return self.callRemote("isRunning")
		
	def sendSignal(self, sig):
		def _sendSignal(s):
			self._process.transport.signalProcess(s)
		d = self.isRunning()	
		d.addCallback(lambda x, s=sig: _sendSignal(s))

class Opsiconfd(OpsiDaemon):
	script = 'opsiconfd'
	user = 'opsiconfd'
	allowMultiple = True


class Supervisor(object):
	
	def __init__(self, config, daemons=[Opsiconfd]):
		self.daemons = []
		self.enabledDaemons = daemons
		self.config = config
		
		self.check = LoopingCall(self.checkRunning)
		signal.signal(signal.SIGHUP, self.reload)
		
	def start(self):
		for daemon in self.enabledDaemons:
			try:

				conf = self.config[daemon.script]
					
				if daemon.allowMultiple 	\
				and "count" in conf.keys()	\
				and int(conf["count"]) > 0:
					instanceCount = int(conf["count"])
				else:
					instanceCount = 1
				
				args = []
				if "args" in conf.keys():
					args=conf["args"].split(" ")
				
				for i in range(instanceCount):
					logger.notice("Starting daemon %s" % daemon.script)
				 	d = daemon(args=args, config=conf)		 	
				 	d.start()
				 	self.daemons.append(d)				 	
			except Exception, e:
				logger.error("Failed to start daemon %s"% (daemon.script))
				logger.logException(e)
				raise
		reactor.callLater(10, self.check.start, 15, True)
		
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
		print isRunning
		if not isRunning and daemon.allowRestart:
			d = daemon.stop()
			d.addCallback(lambda x: daemon.start)
	
	def stop(self):
		if self.check.running:
			self.check.stop()
			
		for daemon in self.daemons:
			daemon.allowRestart = False
			daemon.stop()
			
			
class SupervisionProtocol(ProcessProtocol):
 	
 	def __init__(self, daemon):
 		self.daemon = daemon
 		self.pid = None
 		
 	def connectionMade(self):
 		self.pid = self.transport.pid 		
 		socket = "/var/run/opsiconfd/%s.%s.socket" %(self.daemon.script, self.pid) 	
 		self.daemon._connector = self.daemon.connector(socket=socket)
 		
 	def stop(self):
 		if self.transport.pid:
 			self.defer = Deferred()
 			self.transport.signalProcess(signal.SIGTERM)
 			reactor.callLater(10, self.kill)
 			return self.defer
 		return succeed(None)

 	def kill(self):
 		if self.transport.pid:
 			self.transport.signalProcess(signal.SIGKILL)
 			
	def outReceived(self, data):
		logger.debug2(data)

	def errReceived(self, data):
		logger.debug2(data)
			
	def processEnded(self, reason):
		if self.daemon.allowRestart:
			self.daemon.start()
			defer, self.defer = self.defer, None
			if defer is not None:
				defer.callback(None)
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
		
		self._supervisor = Supervisor(config)
		self.config = config.pop("global")
		self.exitCode = 0
		
	def startService(self):
		Service.startService(self)
		try:
			#daemonize()
			logger.debug2("Starting supervisor.")
			self._supervisor.start()			
		except Exception, e:
			logger.critical(u"Error starting opsi supervision service: %s" %e)
			self.exitCode = 1
			reactor.crash()
			
	def stopService(self):
		Service.stopService(self)
		signal.signal(signal.SIGINT, signal.SIG_IGN)
		
		
		done = self._supervisor.stop()
		#done.addBoth(lambda r: self._remove_pid())
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
	logger.setConsoleLevel(LOG_DEBUG2)
	logger.setConsoleColor(True)
	
	config = {}
	raw = IniFile("/etc/opsi/opsi-daemon.conf", raw = True).parse()
	[config.setdefault(section, dict(raw.items(section))) for section in raw.sections()]

	application = Application("opsi-supervisor")
	service = SupervisionService(config=config)
	service.setServiceParent(application)
	
	reactor.callLater(0, startApplication, application, False)
        reactor.run()
        
        return service.exitCode
	