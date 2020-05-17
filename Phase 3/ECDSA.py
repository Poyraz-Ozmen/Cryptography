#CS411-507 Cryptography Project Phase I 
# M.L. Poyraz Ozmen 23724
# Alper Bingol 23661
import random
import sys
from ecpy.curves import Curve, Point
import secrets
from Crypto.Hash import SHA3_256

def SignVer(message, s, r, curve, Q): 
    H_b = SHA3_256.new(message).digest()
    h = int.from_bytes(H_b, byteorder="big") % curve.order

    k1P_x, k1P_y = Mult_Elliptic(curve.generator.x, curve.generator.y, curve.order - (s * pow(h, curve.order-2, curve.order)) % curve.order, curve)
    k2QA_x, k2QA_y = Mult_Elliptic(Q.x, Q.y, (r * pow(h, curve.order-2, curve.order)) % curve.order, curve)

    k1P_x = k1P_x % curve.field
    k1P_y = k1P_y % curve.field
    k2QA_x = k2QA_x % curve.field
    k2QA_y = k2QA_y % curve.field
    Lamed = 0
    
    if k1P_x == k2QA_x and k1P_y == k2QA_y:
        Lamed = (((3 * ((k1P_x)**2)) + curve.a) * pow(2 * k1P_y, curve.field-2, curve.field)) % curve.field
    else:
        Lamed = ((k1P_y - k2QA_y) * pow(k1P_x - k2QA_x, curve.field-2, curve.field)) % curve.field

    #y = ((Lamed * (k1P_x - ((Lamed**2) - k1P_x - k2QA_x) % curve.field)) -k1P_y) % curve.field

    return 0 if ((((Lamed**2) - k1P_x - k2QA_x) % curve.field) % curve.order == r % curve.order) else 1

def Mult_Elliptic(Px, Py, k, curve):
    
    initial = True

    while k != 0:
        if (k % 2) != 0:
            if initial == True:
                Qx = Px
                Qy = Py
                initial = False
            else:
                Qx = Qx % curve.field 
                Qy = Qy % curve.field 
                Px = Px % curve.field
                Py = Py % curve.field
                Lamed = 0
                if Qx == Px and Qy == Py:
                    Lamed = (((3 * ((Qx)**2)) + curve.a) * pow(2 * Qy, curve.field-2, curve.field)) % curve.field
                else:
                    Lamed = ((Qy - Py) * pow(Qx - Px, curve.field-2, curve.field)) % curve.field

                x = ((Lamed**2) - Qx - Px) % curve.field
                y = ((Lamed * (Qx - x)) -Qy) % curve.field
                
                Qx = x
                Qy = y

        k = k // 2

        if k != 0:
            Lamed = 0

            Px = Px % curve.field 
            Py = Py % curve.field
            Px = Px % curve.field
            Py = Py % curve.field

            if Px == Px and Py == Py:
                Lamed = (((3 * ((Px)**2)) + curve.a) * pow(2 * Py, curve.field-2, curve.field)) % curve.field
            else:
                Lamed = ((Py - Py) * pow(Px - Px, curve.field-2, curve.field)) % curve.field

            x = ((Lamed**2) - Px - Px) % curve.field
            y = ((Lamed * (Px - ((Lamed**2) - Px - Px) % curve.field)) -Py) % curve.field

            Px = x
            Py = y
    
    return Qx, Qy        

def KeyGen(curve):
    
    secret = secrets.randbelow(curve.order-1)
    x, y = Mult_Elliptic(curve.generator.x, curve.generator.y, secret, curve)

    Q = Point(x, y, curve)

    return secret, Q



def SignGen(message, curve, secret):
    H_b = SHA3_256.new(message).digest()

    h = int.from_bytes(H_b, byteorder="big") % curve.order

    r = 0
    s = 0

    while r == 0 or s == 0:
        k = secrets.randbelow(curve.order)

        R_x, R_y = Mult_Elliptic(curve.generator.x, curve.generator.y, k, curve)

        r = (R_x) % curve.order

        s = ((secret * r) - (k * h)) % curve.order

    return s, r


