function lookup_multi(key, lookupFunc, providers) {
	for (let p of providers) {
		let r = p[lookupFunc](key);
		if (r) return r;
	}
	return null;
}
function make_i6t_static_map(objects) {
	let ip_to_domain_map = new Map();
	let domain_to_ip_map = new Map();
	let _result = {ip_to_domain_map: ip_to_domain_map, domain_to_ip_map: domain_to_ip_map};
	_result.lookup_ip = (ipAddress) => ip_to_domain_map.get(ipAddress);
	_result.lookup_domain = (domainName) => domain_to_ip_map.get(domainName);
	for (let o of objects) {
		let o1_bigint = BigInt(o[1]);
		ip_to_domain_map.set(o1_bigint, [o[0], o[2]]);
		domain_to_ip_map.set(o[0], [o1_bigint, o[2]]);
	}
	return _result;
}
function make_prefix_map() {
	let _result = {
		prefix: '',
		ip_base: 0n,
		domain_base: 0n,
		i2d_get_object: (ipAddress, domainName) => null,
		d2i_get_object: (ipAddress, domainName) => null,
		length: 0n,
		padding: 0
	};
	_result.lookup_ip = (ipAddress) => {
		let ipAddress_normalized = ipAddress - _result.ip_base;
		if ((ipAddress_normalized >= 0n) && (ipAddress_normalized < _result.length)) {
			let result_domain_num = ipAddress_normalized + _result.domain_base;
			let result_domain_str = String(result_domain_num);
			for (let i = result_domain_str.length; i < _result.padding; i++) {
				result_domain_str = "0" + result_domain_str;
			}
			result_domain_str = _result.prefix + result_domain_str;
			return [result_domain_str, _result.i2d_get_object(ipAddress, result_domain_str)];
		}
		return null;
	};
	_result.lookup_domain = (domainName) => {
		let match_regexp = new RegExp('^' + _result.prefix + '0*([0-9]+)$');
		let match_result = match_regexp.match(domainName);
		if (match_result) {
			try {
				let num = BigInt(match_result[1]);
				let num_normalized = num - _result.domain_base;
				if ((num_normalized >= 0n) && (num_normalized < _result.length)) {
					let result_ip = num_normalized + _result.ip_base;
					return [result_ip, _result.d2i_get_object(result_ip, domainName)];
				}
			} catch (e) {
			}
		}
		return null;
	};
	return _result;
}
var scp_map = make_prefix_map();
scp_map.prefix = 'scp-';
scp_map.length = 60000n;
scp_map.padding = 3;
var scp_dclass_map = make_prefix_map();
scp_dclass_map.prefix = 'd-';
scp_dclass_map.length = 60000n;
scp_dclass_map.padding = 3;
exports.lookup_multi = lookup_multi;
exports.make_i6t_static_map = make_i6t_static_map;
exports.make_prefix_map = make_prefix_map;
exports.scp_map = scp_map;
exports.scp_dclass_map = scp_dclass_map;
