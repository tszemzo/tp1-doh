def in_domains(hostname, domains):
    return hostname in domains


def _update_ips(original_ips, new_ips):
    diff = set(original_ips).symmetric_difference(set(new_ips))
    original_ips.extend(diff)


def ip_round_robin(resolver_domains, hostname, ip_list):
    if hostname not in resolver_domains:
        resolver_domains[hostname] = ip_list
    else:
        _update_ips(resolver_domains[hostname], ip_list)

    return resolver_domains[hostname].pop(0)
