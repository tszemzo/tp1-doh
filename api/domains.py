from flask import abort, make_response, jsonify, request
import dns.resolver
from . utils import dup, ip_round_robin, in_domains

# Data to serve with our API
domains = {
    'custom2.fi.uba.ar': {
        'domain': 'custom2.fi.uba.ar',
        'ip': '157.92.49.38',
        'custom': True,
    },
    'custom.fi.uba.ar': {
        'domain': 'custom.fi.uba.ar',
        'ip': '1.1.1.1',
        'custom': True,
    },
}

resolver_domains = {}

def obtener_todos():
    """
    Esta funcion maneja el request GET /api/custom-domain

    :return:        200 lista de todos los custom domains creados
    """
    # Falta agregar el param opcional del filtro
    items = []
    for domain in domains:
        items.append(domains[domain])

    response = jsonify(items=items)
    return make_response(response, 200)

def obtener_uno(domain):
    """
    Esta funcion maneja el request GET /api/domains/{domain}

    :domain body: hostname del domain que se quiere obtener
    :return:      200 hostname, 404 domain no encontrado
    """
    if in_domains(domain, domains):
        return domains.get(domain)
    try:
        dns_results = dns.resolver.query(domain)
        dns_records = [ip.address for ip in dns_results]
        response = jsonify( domain=domain,
                            ip=dns_records[0], #ip_round_robin(resolver_domains, domain, dns_records)
                            custom=False)

        return make_response(response, 200)

    except:
        error_msg = jsonify(error='domain not found')
        return make_response( error_msg , 404)
        # return abort(404, 'domain not found')


def crear(**kwargs):
    """
    Esta funcion maneja el request POST /api/custom-domain

    :param body:  custom domain a crear
    :return: 201 custom domain creado, 400 entidad
                con el mismo dominio o bad request
    """
    domain = kwargs.get('body')
    hostname = domain.get('domain')
    ip = domain.get('ip')

    if not ip or not hostname or in_domains(hostname,domains):
        error_msg = jsonify(error='custom domain already exists')
        return make_response( error_msg , 400)
        # return abort(400, 'custom domain already exists')

    else:
        domain['custom'] = True
        domains[hostname] = domain
        return make_response(domain, 201)

def borrar(domain):
    """
    Esta funcion maneja el request DELETE /api/custom-domain/{domain}

    :domain body:  hostname que se quiere borrar
    :return:        200 domain, 404 domain no encontrado
    """
    if domain not in domains:
        error_msg = jsonify( error='domain not found' )
        return make_response(error_msg, 404)
        # return abort(404, 'domain not found')

    domains.pop(domain)
    response = jsonify( domain=domain )
    return make_response(response, 200)

def modificar(domain, **kwargs):
    """
    Esta funcion maneja el request DELETE /api/custom-domain/{domain}

    :domain body:  hostname que se quiere borrar
    :return:        200 domain, 404 domain no encontrado
    """

    updated_domain = kwargs.get('body')
    hostname = updated_domain.get('domain')
    ip = updated_domain.get('ip')

    if not ip or not hostname:
        error_msg = jsonify( error='payload is invalid' )
        return make_response(error_msg, 400)
        # return abort(400, 'payload is invalid')

    elif not in_domains(domain, domains):
        error_msg = jsonify( error='domain not found' )
        return make_response(error_msg, 404)
        # return abort(404, 'domain not found')

    else:
        # In case it is possible to edit domains name, if not domains.pop flys.
        domains.pop(domain)
        domains[hostname] = updated_domain
        return make_response(updated_domain, 200)