"""Opt-in pinned binary tests; all target HTTP/TLS traffic uses loopback fixtures.

RUN_TOOL_TESTS=1 HTTPX_BIN=/path/httpx KATANA_BIN=/path/katana python -m unittest discover -s tests -p test_v86_tool_runtime.py
"""
import os
import shutil
import ssl
import unittest
from urllib.request import HTTPSHandler, ProxyHandler, build_opener
from guarded_probe import command as probe_command, supervise
from guarded_crawl import command as crawl_command
from recon81.guard import NoRedirect, ProtectedHTTP, RunGuard
from recon81.protected_proxy import ProtectedProxy
from test_v86_network import NetworkFixture


@unittest.skipUnless(os.environ.get('RUN_TOOL_TESTS')=='1','Enable RUN_TOOL_TESTS with pinned httpx and Katana binaries')
class ToolRuntimeTests(NetworkFixture):
    def exercise(self, name, builder):
        binary = os.environ.get(name.upper()+'_BIN') or shutil.which(name)
        self.assertTrue(binary, name+' binary is required when RUN_TOOL_TESTS=1')
        for tls in (False,True):
            with self.subTest(tool=name,tls=tls):
                self.hits.clear()
                guard = RunGuard(self.root/(name+str(tls)+'.db'),max_requests=20,interval=0)
                try:
                    with ProtectedProxy(self.policy,guard) as gateway:
                        if tls:
                            self.server.socket = gateway.tls_context('127.0.0.1').wrap_socket(self.server.socket,server_side=True)
                            def client_factory():
                                client = ProtectedHTTP(self.policy,guard)
                                client.opener = build_opener(ProxyHandler({}),NoRedirect(),HTTPSHandler(context=ssl.create_default_context(cafile=str(gateway.ca))))
                                return client
                            gateway.client_factory = client_factory
                        base = self.url.replace('http:','https:') if tls else self.url
                        seeds = self.root/(name+str(tls)+'.txt')
                        # The allowed entry contains /delete1 links, which the old
                        # Katana regex missed. Redirect destination has the same path.
                        seeds.write_text(base+'/ok\n'+base+'/redirect\n')
                        argv = builder(binary,seeds,self.policy) if name=='katana' else builder(binary,seeds)
                        output = self.root/(name+str(tls)+'.jsonl')
                        code = supervise(gateway.command(argv),output,guard,self.policy,deadline=30,kind=name,
                                         env=gateway.environment(),transport=gateway)
                        self.assertEqual(0,code,'Controlled '+name+' failed against local fixture')
                        self.assertIn('/ok',self.hits)
                        self.assertIn('/redirect',self.hits)
                        self.assertNotIn('/delete1',self.hits)
                        self.assertEqual(len(self.hits),guard.state()['requests'])
                        self.assertGreater(guard.state()['bytes'],0)
                        self.assertTrue(output.read_text().strip())
                finally: guard.close()

    def test_httpx_http_and_https_policy_gateway(self):
        self.exercise('httpx',probe_command)

    def test_katana_http_and_https_policy_gateway(self):
        self.exercise('katana',crawl_command)


if __name__ == '__main__': unittest.main()
