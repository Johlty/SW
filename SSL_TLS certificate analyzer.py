import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timezone

def analyze_certificate(cert):
    try:
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            print("Сертифікат використовує RSA шифрування.")
            print(f"Довжина RSA ключа: {public_key.key_size} біт")
            if public_key.key_size < 2048:
                print("Попередження: RSA ключ менше 2048 біт вважається ненадійним!")
        
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            print("Сертифікат використовує ECC шифрування.")
            print(f"Крива: {public_key.curve.name}")
        else:
            print("Невідомий тип шифрування.")
        
        expiration_date = cert.not_valid_after_utc
        if expiration_date < datetime.now(timezone.utc):
            print("Сертифікат недійсний (пройшов термін дії).")
        else:
            print("Сертифікат дійсний.")
        print(f"Сертифікат дійсний до: {expiration_date}")
    
    except Exception as e:
        print(f"Помилка при аналізі сертифіката: {e}")

def get_ssl_certificate(hostname):
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                return cert
    except socket.gaierror:
        print("Помилка з'єднання: неможливо знайти адресу. Перевірте правильність введення домену.")
    except socket.timeout:
        print("Помилка з'єднання: час з'єднання перевищено.")
    except ssl.SSLError as e:
        print(f"Помилка SSL: {e}")
    except Exception as e:
        print(f"Непередбачена помилка: {e}")
    return None

if __name__ == "__main__":
    hostname = input("Введіть назву сайту для аналізу (без 'https://'): ").strip()
    cert = get_ssl_certificate(hostname)
    if cert:
        analyze_certificate(cert)




