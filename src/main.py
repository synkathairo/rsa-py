import base64
import math
import secrets
import sys

from textwrap import wrap

VALID_ALGORITHMS: list[str] = ["rsa"]
RSA_PRIVATE_START: str = "-----BEGIN RSA PRIVATE KEY-----"
RSA_PRIVATE_STOP: str = "-----END RSA PRIVATE KEY-----"
RSA_PUBLIC_START: str = "-----BEGIN PUBLIC KEY-----"
RSA_PUBLIC_STOP: str = "-----END PUBLIC KEY-----"
# small odd integer e that is relatively prime to φ(n)
# integer e such that 1 < e < λ(n)
# KNOWN_TOTIENT_E: int = 65537
KNOWN_TOTIENT_E: int = 3


def _is_prime(num: int) -> bool:
    """
    Use the (naive) Sieve of Eratosthenes method of prime checking
    """
    num_sqrt_floor = math.floor(math.sqrt(num))

    for i in range(2, num_sqrt_floor + 1):
        if num % i == 0:
            return True

    return False


def _prime_generator(length: int) -> int:
    prime_num: int = 2
    while True:
        prime_num = secrets.randbits(length)
        if _is_prime(prime_num):
            break
    return prime_num


# adopted from pseudocode at https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
def _extended_euclidean_modular_inverse(a: int, n: int) -> int:
    t: int = 0
    new_t: int = 1
    r: int  = n
    new_r: int = a

    while (new_r!=0):
        quotient = r//new_r
        hold_t = t
        t = new_t
        new_t = hold_t - quotient * new_t
        hold_r = r
        r = new_r
        new_r = hold_r - quotient * new_r
    
    if r > 1:
        # a not invertible
        return -1
    if t < 0:
        t = t + n
    return t


def _generate_rsa_key(length: int) -> str:
    # first, generate valid primes
    p: int = _prime_generator(length)
    q: int = _prime_generator(length)

    n: int = p * q

    totient_lambda = (p - 1) * (q - 1)  
    # since they are prime, no need to do lcm
    # math.lcm(p-1,q-1)

    # while True:
    #     e_val: int = secrets.randbelow(totient_lambda)
    #     # e_val = KNOWN_TOTIENT_E
    #     if totient_lambda%e_val!=0:
    #         break

    e_val = KNOWN_TOTIENT_E

    # e_mod_phi_n = e_val % totient_lambda

    # d_val: int = 12
    # d_val = 1 / e_mod_phi_n
    d_val = _extended_euclidean_modular_inverse(e_val, totient_lambda)
    # print("d_val: ", d_val)

    # bytes(d_val)
    # "{:X}".format(n)
    # str(base64.standard_b64encode(str(d_val).encode()))

    # TODO: careful, as ascii '1' does not map to 0b1
    # TODO: should this be big endian?
    # TODO: we use length below, but keys are supposed to be variable length? (remove filler?)
    d_val_pre_str = str(
        base64.standard_b64encode(int.to_bytes(d_val, length, byteorder="big"))
    )
    d_val_str_result = d_val_pre_str[2 : (len(d_val_pre_str) - 1)]

    d_val_str = "\n".join(wrap(d_val_str_result, 64))

    return RSA_PUBLIC_START + "\n" + d_val_str + "\n" + RSA_PUBLIC_STOP


def run_task(arguments: list[str], arg_len: int) -> str:
    # defaults
    length: int = 8
    algorithm_type: str = "rsa"
    key_str: str

    i = 0
    while i < arg_len:
        cur_arg: str = arguments[i]
        match cur_arg:
            case "--length":
                try:
                    length = int(arguments[i + 1])
                    i += 1
                except IndexError:
                    print("length not specified")
                except ValueError:
                    print("please specify a valid length")
            case "--algorithm":
                try:
                    algorithm_type = arguments[i + 1]
                    if algorithm_type not in VALID_ALGORITHMS:
                        raise ValueError
                    else:
                        i += 1
                except (ValueError, IndexError):
                    print("please specify a valid algorithm")
            case _:
                pass
        i += 1
    match algorithm_type:
        case _:
            key_str = _generate_rsa_key(length)
    return key_str


# run the task!
arguments: list[str] = sys.argv
arg_len = len(arguments)
key_str_result: str = run_task(arguments, arg_len)
print(key_str_result)
