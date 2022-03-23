import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype


NAMESERVER='1.1.1.1'
ROOTKEYS = dns.rrset.from_text_list('.', 3600, 'IN', 'DNSKEY', ['256 3 8 AwEAAZym4HCWiTAAl2Mv1izgTyn9sKwgi5eBxpG29bVlefq/r+TGCtmU ElvFyBWHRjvf9mBglIlTBRse22dvzNOI+cYrkjD6LOHuxMoc/d4WtXWK dviNmrtWF2GpjmDOI98gLd4BZ0U/lY847mJP9LypFABZcEn3zM3vce4E e1A3upSlFQ2TFyJSD9HvMnP4XneFexBxV96RpLcy2O+u2W6ChIiDCjlr owPCcU3zXfXxyWy/VKM6TOa8gNf+aKaVkcv/eIh5er8rrsqAi9KT8O5h mhzYLkUOQEXVSRORV0RMt9l3JSwWxT1MebEDvtfBag3uo+mZwWSFlpc9 kuzyWBd72Ec=','257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU='])


def _get_soa(domain: str) -> str:

    #qry = dns.resolver.resolve(domain, dns.rdatatype.SOA, raise_on_no_answer=False)
    qry = dns.message.make_query(domain, dns.rdatatype.SOA)
    answ = dns.query.udp(qry, NAMESERVER)

    if len(answ.authority) != 0:
        authority = answ.authority[0].to_text().split(' ')[0]
        return authority
    else:
        return domain


def _get_records(domain: str, record: dns.rdatatype = None) -> {}:

    retval = False
    if domain != ".":
        soaname = _get_soa(domain)
    else:
        soaname = "."

    nsaddr = NAMESERVER

    # get DNSKEY for zone
    req = dns.message.make_query(soaname, dns.rdatatype.DNSKEY, want_dnssec=True)
    qry = dns.query.udp(req, nsaddr)

    # check if query was successful
    if qry.rcode() != 0:
        print("QUERY FAILED")
        return None

    # we should have the dnskeys and the rrset signature now, otherwise try again with tcp
    if len(qry.answer) < 2:
        qry = dns.query.tcp(req, nsaddr)
        # check if query was successful
        if qry.rcode() != 0:
            print("QUERY FAILED")
            return None

        if len(qry.answer) < 2:
            return None

    if domain != ".":
        # get DS record
        reqDS = dns.message.make_query(soaname, dns.rdatatype.DS, want_dnssec=True)
        qryDS = dns.query.tcp(reqDS, nsaddr)

        # check if query was successful (rcode can only be positive)
        if qryDS.rcode() != 0:
            print("QUERY FAILED")
            return None

        # we should have the dnskeys and the rrset signature now
        if len(qryDS.answer) < 2:
            return None

    if record != None:
        # get specified record
        reqX = dns.message.make_query(domain, record, want_dnssec=True)
        qryX = dns.query.tcp(reqX, nsaddr)

        # check if query was successful (rcode can only be positive)
        if qryX.rcode() != 0:
            print("QUERY FAILED")
            return None

        # we should have the dnskeys and the rrset signature now
        if len(qryX.answer) < 2:
            return None

    # return the infos
    name = dns.name.from_text(soaname)
    retval = {"name": name, "dnskey": qry.answer}

    if domain != ".":
        retval["ds"] = qryDS.answer

    if record != None:
        retval[dns.rdatatype.to_text(record)] = qryX.answer

    return retval
    
def _gen_ds(dnskeys: [], name: str) -> []:
    """
    calculates the DS values of the KSKs
    dnskeys TODO
    name TODO
    """
    ksks = []
    for key in dnskeys:
        if key.to_text()[:3] == "257":
            ksks.append({"key": key, "ds": dns.dnssec.make_ds(name, key, "SHA256")})
    return ksks
    

def _validate_ds(dscalc: [], dsdns: []) -> bool:
    """
    dscalc: Calculated DS for the DNSKEYs
    dsdns: Value of DS Record of the parent zone
    """
    for dsmap in dscalc:  # for each dnskey
        if dsmap["ds"] not in dsdns:  # check if ALL DS-Hashes of the DNSKEYs is in the set of the parent DS records
            return False  # if not, return false

    return True  # if all DS hashes are valid, return true


def _order_sets(rndlist: []) -> dict:
    """
    extract rrset and rrsig; because they can be mixed up
    """
    retval = {}
    for rcd in rndlist:
        if type(rcd[0]) == dns.rdtypes.ANY.RRSIG.RRSIG:
            retval["RRSIG"] = rcd
        else:
            retval["RRSET"] = rcd
    return retval


def get_validated_record(domain: str, recordtype: dns.rdatatype):

    retval = False

    child = None
    answer = None
    for i in range(domain.count(".")+1):

        curname = child["name"].to_text().split(".", 1)[1] if child != None else domain
        if curname == "":
            curname = "."

        record = recordtype if i == 0 else None
        current = _get_records(curname, record)

        try:

            # validate RRSIG of DNSKEYs within the zone
            dns.dnssec.validate(_order_sets(current["dnskey"])["RRSET"], _order_sets(current["dnskey"])["RRSIG"], {current["name"]: current["dnskey"][0]})

            # validate RRSIG of WANTED record // only in the first round
            if record != None:
                dns.dnssec.validate(_order_sets(current[dns.rdatatype.to_text(record)])["RRSET"],
                                    _order_sets(current[dns.rdatatype.to_text(record)])["RRSIG"],
                                    {current["name"]: current["dnskey"][0]})

                # set answer if successful (meaning no exception)
                answer = _order_sets(current[dns.rdatatype.to_text(record)])["RRSET"]

            # validate DS record of the child // except for the first round
            if i != 0:
                dns.dnssec.validate(_order_sets(child["ds"])["RRSET"], _order_sets(child["ds"])["RRSIG"], {current["name"]: current["dnskey"][0]})  # if this is OK then we can trust the DS for ...

            if curname != ".":  # validate if the DS record hash is correct // except for the last round (root)

                # calculate the ds values of the dnskeys
                dslist = _gen_ds(_order_sets(current["dnskey"])["RRSET"], current["name"].to_text())  # calculate ds for each dnskey

                # validate the calculated ds keys with the ds record
                if not _validate_ds(dslist, _order_sets(current["ds"])["RRSET"]):
                    return False  # return False if at least one of them is not valid

            retval = True

            # last check: are the root keys correct?
            if curname == ".":
                retval = current["dnskey"][0] == ROOTKEYS
                break

        except Exception as e:
            # Exception if
            # - Record was invalid
            # - DNSSEC was not available
            # print("===== EXCEPTION =====", e)
            return False

        print(current["name"].to_text(),":",retval)
        child = current.copy()  # last is as child zone

    return answer

if __name__ == '__main__':
    TARGET='fwsrv1.mup.dnssec-uni-potsdam.de'
    #print(get_validated_record(TARGET, dns.rdatatype.A))
    print(get_validated_record("_443._tcp.fwsrv1.mup.dnssec-uni-potsdam.de", dns.rdatatype.TLSA))
    #print(get_validated_record("cafecafe.keystore.mup.dnssec-uni-potsdam.de", dns.rdatatype.IPSECKEY))
