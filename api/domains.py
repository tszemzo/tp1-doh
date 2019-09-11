from flask import abort, make_response, jsonify
import dns.resolver
from . utils import is_custom

# Data to serve with our API
domains = {
    'fi.uba.ar': {
        'domain': 'fi.uba.ar',
        'ip': '157.92.49.38',
        'custom': False,
    },
    'custom.fi.uba.ar': {
        'domain': 'fi.uba.ar',
        'ip': '1.1.1.1',
        'custom': True,
    },
}

def obtener_uno(domain):
    """
    Esta funcion maneja el request GET /api/domains/{domain}

    :domain body: hostname del domain que se quiere obtener
    :return:      200 hostname, 404 domain no encontrado
    """
    if domain not in domains:
        return abort(404, 'domain not found')
    elif is_custom(domain):
        return domains.get(domain)
    else:
        ## Falta agregar el Round Robin
        dns_results = dns.resolver.query(domain)
        dns_records = [ip.address for ip in dns_results]
        response = jsonify( domain=domain,
                            ip=dns_records[0],
                            custom=False)

        return make_response(response, 200)