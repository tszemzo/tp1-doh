def is_custom(hostname):
    return hostname.split('.')[0] == 'custom'

def dup(new_domain, domains):
	dup = False
    for existent_domain in domains:
        dup = new_domain == existent_domain.get('domain')
        if dup: return True

def ip_round_robin(domains, hostname, ip_list):
	count_ips = len(ip_list)
	if not domains[hostname] or domains[hostname] == count_ips: 
		domains[hostname] = 0
	else: 
		domains[hostname] += 1

	return ip_list[domains[hostname]]