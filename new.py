import argparse
import base64
import binascii
import configparser
import os
import sys
import zlib
from lxml import etree
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from OpenSSL.crypto import load_pkcs12
import warnings
warnings.filterwarnings("ignore")


def _int_to_bytes(number):
	return number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')


def _key_from_xml(node, backend):
	mod = int.from_bytes(base64.b64decode(node.xpath('RSAKeyValue/Modulus')[0].text), byteorder='big')
	exp = int.from_bytes(base64.b64decode(node.xpath('RSAKeyValue/Exponent')[0].text), byteorder='big')
	return RSAPublicNumbers(exp, mod).public_key(backend)


def _key_to_xml(key, root):
	numbers = key.public_numbers()
	node = etree.SubElement(root, 'RSAKeyValue')
	etree.SubElement(node, 'Modulus').text = base64.b64encode(_int_to_bytes(numbers.n))
	etree.SubElement(node, 'Exponent').text = base64.b64encode(_int_to_bytes(numbers.e))


def decode(data, key, iv):
	backend = default_backend()

	doc = etree.fromstring(data)
	node = doc.xpath('/ARCHIVE/RADIO')[0]
	encrypted = base64.b64decode(node.text)

	decryptor = Cipher(AES(key), CBC(iv), backend=backend).decryptor()
	compressed = decryptor.update(encrypted) + decryptor.finalize()

	signed = zlib.decompress(compressed, 16 + zlib.MAX_WBITS)
	if signed[:3] != b'\xef\xbb\xbf':
		raise Exception('Invalid header')

	signature_pos = signed.rfind(b'<SIGNATURE>')
	payload = signed[3:signature_pos]
	signature = etree.fromstring(signed[signature_pos:])

	digest = bytes.fromhex(signature.xpath('DIGEST')[0].text)
	key = _key_from_xml(signature, backend)
	key.verify(digest, payload.decode('utf-8').encode('utf-16-le'), PKCS1v15(), SHA1())

	return payload


def build(payload, signing_key, key, iv, backend):
	backend = signing_key._backend

	signature = signing_key.sign(payload.decode('utf-8').encode('utf-16-le'), PKCS1v15(), SHA1())

	sign_doc = etree.Element('SIGNATURE')
	etree.SubElement(sign_doc, 'VERSION').text = '1.0'
	etree.SubElement(sign_doc, 'DIGEST').text = binascii.hexlify(signature).decode().upper()
	_key_to_xml(signing_key.public_key(), sign_doc)

	signed = b'\xef\xbb\xbf' + payload + etree.tostring(sign_doc)

	compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
	compressed = compressor.compress(signed) + compressor.flush()

	padder = PKCS7(len(iv) * 8).padder()
	padded = padder.update(compressed) + padder.finalize()

	encryptor = Cipher(AES(key), CBC(iv), backend=backend).encryptor()
	encrypted = encryptor.update(padded) + encryptor.finalize()

	doc = etree.Element('ARCHIVE')
	doc.set('TYPE', 'GEMSTONE')
	node = etree.SubElement(doc, 'RADIO')
	node.set('VERSION', '1')
	node.set('ENCODING', 'Base64')
	node.text = base64.b64encode(encrypted)

	return etree.tostring(doc)


def _read_config(filename):
	config = configparser.ConfigParser()
	config['codeplug'] = {}
	config_dict={}
	if filename:
		config.read_file(open(filename, 'r'))
	elif os.path.isfile('codeplug.cfg'):
		config.read_file(open('codeplug.cfg', 'r'))
	for key, value in os.environ.items():
		if key.startswith('CODEPLUG_'):
			config['codeplug'][key[9:].lower()] = value
	if 'key' not in config['codeplug']:
		raise Exception('Invalid configuration')
	for i in config['codeplug']:
		config_dict[i]=config['codeplug'][i]
	return config_dict


def decode_cmd(config,ctb_file_name):
	try:
		with open(ctb_file_name, 'rb') as f:
			data = f.read()
	
		result = decode(data, base64.b64decode(config['key']), base64.b64decode(config['iv']))
		xml = etree.fromstring(result)
		write_file(ctb_file_name.replace(".ctb",".xml"),etree.tostring(xml, pretty_print=True))
	except Exception as err:
		raise err
	else:
		return xml


def build_cmd(config,xml_file_name):
	try:
		backend = default_backend()
	
		payload = etree.tostring(etree.parse(xml_file_name))
	
		if 'signing_password' in config:
			signing_key = load_pkcs12(base64.b64decode(config['signing_key']), base64.b64decode(config['signing_password'])).get_privatekey().to_cryptography_key()
		else:
			signing_key = load_pem_private_key(config['signing_key'].encode('ascii'), password=None, backend=backend)
	
		result = build(payload, signing_key, base64.b64decode(config['key']), base64.b64decode(config['iv']), backend)
	
		write_file(xml_file_name.replace(".xml",".ctb"),result)
	except Exception as err:
		raise err
	else:
		return result

def write_file(file_name,result):
	try:
		with open(file_name, 'wb') as f:
			f.write(result)
	except Exception as err:
		raise err


def create_add_CallSign(user_list,Lasted_ID):
	try:
		Start_ID=Lasted_ID+1
		Add_CallSign_str=""
		for i in user_list:
			DMR_ID=i.split(",")[0]
			name="DMR_"+i.split(",")[1]+"_"+i.split(",")[2]
			format_str=f'''\n            <DIGITAL_UCL_DLL_TYPE Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">
              <DIGITAL_UCL_DLL_TYPE_NTLLISHTYPE Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">DIGITAL_UCL_DLL_TYPE</DIGITAL_UCL_DLL_TYPE_NTLLISHTYPE>
              <DIGITAL_UCL_DLL_TYPE_NTLLISHID Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">{Start_ID+1}</DIGITAL_UCL_DLL_TYPE_NTLLISHID>
              <DU_LLEQ Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">1</DU_LLEQ>
              <DU_CALLTYPE Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">PRIVCALL</DU_CALLTYPE>
              <DU_CALLTYPEPART1 Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">2</DU_CALLTYPEPART1>
              <DU_CALLTYPEPART2 Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">0</DU_CALLTYPEPART2>
              <DU_UKPOTCFLG Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">0</DU_UKPOTCFLG>
              <DU_CALLPRCDTNEN Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">1</DU_CALLPRCDTNEN>
              <DU_ROUTETYPE Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">REGULAR</DU_ROUTETYPE>
              <DU_TXTMSGALTTNTP Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">REPETITIVE</DU_TXTMSGALTTNTP>
              <DU_RVRTPERS TypeID="SELECTED" Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">0</DU_RVRTPERS>
              <DU_RVRTPERSTYPE Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">SELECTED</DU_RVRTPERSTYPE>
              <DU_RVRTPERSID Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">0</DU_RVRTPERSID>
              <DU_CALLLSTID Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">{DMR_ID}</DU_CALLLSTID>
              <DU_CALLALIAS Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">{name[:16]}</DU_CALLALIAS>
              <DU_RINGTYPE Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">NOSTYLE</DU_RINGTYPE>
              <DU_CONNECTTYPE Applicable="Disabled" ListID="0" ListLetID="{Start_ID}">USB</DU_CONNECTTYPE>
              <DUL_RESERVED Applicable="Enabled" ListID="0" ListLetID="{Start_ID}">0</DUL_RESERVED>
            </DIGITAL_UCL_DLL_TYPE>'''
			Start_ID+=1
			Add_CallSign_str+=format_str
	except Exception as err:
		raise err
	else:
		return Add_CallSign_str


def main():
	source_name='Untitled1.ctb'
	config_dict = _read_config('codeplug.cfg')
	xml=decode_cmd(config_dict,source_name)
	for APP_PARTITION in xml.getiterator('APP_PARTITION'):
		for DIGITAL_UCL_DLH_TYPE_GRP in APP_PARTITION.getiterator('DIGITAL_UCL_DLH_TYPE_GRP'):
			for DIGITAL_UCL_DLT_TYPE in DIGITAL_UCL_DLH_TYPE_GRP.getiterator('DIGITAL_UCL_DLT_TYPE'):
				for DIGITAL_UCL_DLL_TYPE in DIGITAL_UCL_DLT_TYPE.getiterator('DIGITAL_UCL_DLL_TYPE'):
					if DIGITAL_UCL_DLL_TYPE.find('DU_CALLALIAS').text[:4]=='DMR_':
						DIGITAL_UCL_DLT_TYPE.remove(DIGITAL_UCL_DLL_TYPE)



	ID_List=(xml.xpath('//DIGITAL_UCL_DLL_TYPE/@ListLetID'))
	Max_ID=0
	for i in ID_List:
		if int(i)>Max_ID:
			Max_ID=int(i)

	user_list= open("name_list.txt", "r").read().replace(" ","").split("\n")
	Add_CallSign_str=create_add_CallSign(user_list,Max_ID)
	new_xml_str=etree.tostring(xml, pretty_print=True).decode()
	new_xml_str=new_xml_str.replace("</DIGITAL_UCL_DLT_TYPE>",Add_CallSign_str+"\n      </DIGITAL_UCL_DLT_TYPE>").encode()
	write_file(source_name.replace(".ctb","_new.xml"),new_xml_str)
	build_cmd(config_dict,source_name.replace(".ctb","_new.xml"))






if __name__ == '__main__':
	main()
