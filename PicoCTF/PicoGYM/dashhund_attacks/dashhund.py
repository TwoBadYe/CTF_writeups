from math import isqrt
from Crypto.Util.number import long_to_bytes

def continued_fraction(a, b):
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    return cf

def convergents(cf):
    num_prev, num = 0, 1
    den_prev, den = 1, 0

    for a in cf:
        num_next = a * num + num_prev
        den_next = a * den + den_prev

        yield num_next, den_next

        num_prev, num = num, num_next
        den_prev, den = den, den_next


def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1         
        discr = s * s - 4 * n
        if discr < 0:
            continue
        t = isqrt(discr)
        if t * t != discr:
            continue
        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == n:
            return d, p, q
    return None, None, None


if __name__ == "__main__":
    e = 45771007781158680608496659996599690315460595377440379197474537711110445991227035990492734127455230918186631649731168154838429054984598185335586779451084092763576569665328431650500278769098665763121934633683311503433637996263090102383472816027370376882025313929904333871061530691929806094627505122292542935899
    n = 123945209040332233342271723530703509357225115886430688891574381652736426025041656312801003974455720496909908705308569063498846089784422386479269447615141677366713713181441945556405082936686163612606634068432213937191210837057983710032164316568147581894992061437640932687137171282226008152947072295977569638719
    c = 100174780819096491760307564305957136080179791603910582113439016082258277238803432849074611376172469751839823627824725858631175384624471216184942784387766624585305323051519857112788473312875271606831689177575144410034879109180262660630446178745381379209848024503627815116743357196760774465941395767136257746240

    d, p, q = wiener_attack(e, n)

    if d is None:
        print(" Not vulnerable ")
    else:
        m = pow(c, d, n)
        print("Decrypted bytes:", long_to_bytes(m))
        print("Decrypted text :", long_to_bytes(m).decode(errors="ignore"))