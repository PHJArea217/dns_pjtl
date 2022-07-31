const fake_dns = require('./universal-relay/fake_dns.js');
const endpoint = require('./universal-relay/endpoint.js');
const dns_helpers = require('./universal-relay/dns_helpers.js');
const express = require('express');
var domain_manager = dns_helpers.make_soa_ns_handler('apps-vm8.srv.peterjin.org. dns.peterjin.org. 1 10000 10000 10000 120', ['apps-vm8.srv.peterjin.org.'/*,'apps-vm16-alt.srv.peterjin.org.'*/]);
domain_manager.addDomain('0.a.6.0.8.0.2.0.6.2.ip6.arpa');
domain_manager.addDomain('208.161.23.in-addr.arpa');
domain_manager.addDomain('as398565.net');
domain_manager.addDomain('ipv6-things.com');
domain_manager.addDomain('ipv6.bible');
domain_manager.addDomain('peterjin.com');
domain_manager.addDomain('rdns.peterjin.org');
var acme_manager = dns_helpers.make_acme_challenge_handler();
var pdns_app = express();
var acme_app = express();
acme_app.use(express.urlencoded());
acme_manager.make_express_app(acme_app);
var example_com_records_map = new Map();
acme_manager.addKey('as398565.net');
acme_manager.addKey('colors.ipv6-things.com');
acme_manager.addKey('ipv6-things.com');
acme_manager.addKey('ipv6.bible');
acme_manager.addKey('misc.ipv6-things.com');
acme_manager.addKey('peterjin.com');
acme_manager.addKey('ptable.ipv6-things.com');
acme_manager.addKey('scp.ipv6-things.com');
example_com_records_map.set('_acme-challenge', acme_manager.getAcmeChallengeTXTFunc(['as398565.net']));
example_com_records_map.set('_dmarc', [[{qtype: "TXT", content: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@email.peterjin.org"}], null]);
example_com_records_map.set('', [[null, {qtype: 'A', content: '172.104.25.121'}, {qtype: 'AAAA', content: '2600:3c03::f03c:92ff:fe5e:331f'}, {qtype: "TXT", content: "v=spf1 -all"}], null]);
example_com_records_map.set('www', [[{qtype: 'A', content: '172.104.25.121'}, {qtype: 'AAAA', content: '2600:3c03::f03c:92ff:fe5e:331f'}], null]);
var mapping = dns_helpers.make_lookup_mapping(example_com_records_map, null);
var m = fake_dns.make_urelay_ip_domain_map(0x100000000000000n, function(domain_parts, ep, extra_args) {
	if (extra_args[3] === 2) {
		if (domain_manager.getSOANS(ep).length > 0) return {"PRESIGNED": ['0']};
		return {};
	}
	let result = [];
	result.push(...(domain_manager.getSOANS(ep)));
	ep.getSubdomainsOfThen(['net', 'as398565'], Infinity, function (res, t) {
		if (res[0] === 'rdns') {
			let s = res.slice(1).join('|');
			let m = s.match('^([0-9a-z]+-[0-9]+)-([0-9]+)\\|([0-9a-f]+)$');
			if (m) {
				try {
					let src = m[1];
					let major64 = BigInt(m[2]);
					let minor64 = BigInt('0x' + m[3]);
					if (!(major64 >= 0n)) return;
					if (!(minor64 >= 0n)) return;
					let ip_ep = new endpoint.Endpoint();
					switch (src) {
						case 'a-0':
							if (major64 >= 0x100000n) return;
							if (minor64 >= (1n << 64n)) return;
							ip_ep.setIPBigInt((0x26020806a000n << 80n) | (major64 << 64n) | minor64);
							break;
						case 'a-1':
							if (major64 >= 256n) return;
							if (minor64 >= 1n) return;
							ip_ep.setIPBigInt(0xffff17a1d000n | major64);
							break;
						case 'li-0':
							if (major64 >= 0x10000n) return;
							if (minor64 >= (1n << 40n)) return;
							ip_ep.setIPBigInt((0x26003c00e00003061f00n << 48n) | (major64 << 40n) | minor64);
							break;
						case 'li-1':
							if (major64 >= 0x10000n) return;
							if (minor64 >= (1n << 40n)) return;
							ip_ep.setIPBigInt((0x26003c03e00002331f00n << 48n) | (major64 << 40n) | minor64);
							break;
						default:
							return;
					}
					let ip_string = ip_ep.getIPString();
					if (ip_string.indexOf(':') >= 0) {
						result.push({qtype: 'AAAA', content: ip_string});
					} else {
						result.push({qtype: 'A', content: ip_string});
					}
				} catch (e) {
					// console.log(e);
					return;
				}
				return;
			}
		}
		let r = mapping.lookup(res.join('|'));
		if (r) {
			result.push(...r.rrset);
		}
	});
	ep.getSubdomainsOfThen(['arpa'], Infinity, function (res, t) {
		let ip_result = -1n;
		switch (res[0]) {
			case 'in-addr':
				ip_result = dns_helpers.handle_inaddr_arpa(res.slice(1));
				break;
			case 'ip6':
				ip_result = dns_helpers.handle_ip6_arpa(res.slice(1));
				break;
		}
		if (ip_result >= 0n) {
			let rdns_ep = (new endpoint.Endpoint()).setIPBigInt(ip_result);
			rdns_ep.getHostNRThen(0xffff17a1d000n, 120, (res, t) => {
				result.push({qtype: 'PTR', content: `0.a-1-${res}.rdns.as398565.net.`});
			});
			rdns_ep.getHostNRThen(0x26020806a0n << 88n, 44, (res, t) => {
				let major64 = res >> 64n;
				let minor64 = res & ((1n<<64n)-1n);
				result.push({qtype: 'PTR', content: `${minor64.toString(16)}.a-0-${major64}.rdns.as398565.net.`});
			});
		}
	});
	return result;
}, {domainList: domain_manager.domainList, haveDomainMetadata: true});
m.make_pdns_express_app(pdns_app, null, true);
pdns_app.listen({host: '127.0.0.10', port: 8181});
// acme_app.listen('/home/henrie/gitprojects/universal-relay/test/acme.sock');
