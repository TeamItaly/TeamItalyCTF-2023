from sage.schemes.elliptic_curves.hom_composite import EllipticCurveHom_composite
import os
import sys

sys.path.insert(1, "SQISign-SageMath")

from setup import Fp4, E0, p, T_prime, l, f_step_max, e, Dc, O0, T
from ideals import left_isomorphism, pushforward_ideal
from isogenies import torsion_basis, EllipticCurveIsogenyFactored, dual_isogeny
from deuring import kernel_to_ideal, IdealToIsogenyFromKLPT
from KLPT import EquivalentSmoothIdealHeuristic, small_equivalent_ideal, EquivalentPrimeIdealHeuristic, SigningKLPT
from compression import decompression, compression, isogeny_into_blocks
from SQISign import SQISign

z4 = Fp4.gens()[0]

### output ###
EA_coeffs = [61477342232601774540898344438982198710129190332425322879382492699119876782295*z4^3 + 12265701388898022908176476104881258287815505039898709632617507300880123217704*z4 + 69570710034336926246927561034729317055234140290987919877752778751890017423071, 44314008496721078103488998972872233069496210668860153354609525870665543045266*z4^3 + 29429035124778719345585821570991223928448484703463879157390474129334456954733*z4 + 72137132981692760945431553938723170043109738995492125700875782998816234736803]
E10_coeffs = [28520768235685191661247149799086589984387000998399407938653489287530074305178*z4^3 + 45222275385814605787827670744776867013557694373924624573346510712469925694821*z4 + 23487411508466873138898866892658465045402163389790986914186486112153514314303, 7757141784047850947667726233161799882049554051659135145868107716052010908093*z4^3 + 65985901837451946501407094310701657115895141320664897366131892283947989091906*z4 + 32704341731966441563842923079168973246885931178790286251221584998470874878621]
S0 = '000011010111111111100001001110000000011010100001000001011100110100100001001000111100011100000011101111000000011010010110010110011111100110000100001010110001000000110101110100011100110110010111001011001111000001011110001001000010011110001010010000011111000101100001111010010100000000010111011100100101100110110001000001000110101011111001010101110100010010000110000011010000101110000100111000100101000101110010111010110000011100110001101101110000101001100001001101001010101011011111011001000010101011101000011101011110001011000101010101000111111010101001110000000000001100011100110101001101000000001001101001101011110011001010101000101010011011000000011101000111000001100001011110111001001110101001100010100001110011010110101011010100001010011011110001111111000011010110001010101111011000000000010110011001010001001000100111110000110100001001011010100101001110111010011111100000100100010000011000001011101011001000000000101010001110010010011110000111101001110111101100110000000000001000010000010011101010101101101000011010111101011101101101110001011000101100011110100001101010010110100011100011111100100001001111011011000010000000000000000000000011111000'
E11_coeffs = [24267424610470174292521308378992422082338664553856759099734341657483667524703*z4^3 + 49475619011029623156553512164871034915606030818467273412265658342516332475296*z4 + 25396642935463135525382193223342560797101605487174235255231092314383562174944, 55197660504023435387086869245714119826216240210285337594180567617658306423569*z4^3 + 18545383117476362061987951298149337171728455162038694917819432382341693576430*z4 + 44254721219553949680743538274143037194240144203100055318735453258859463983244]
S1 = '101000110000100011001011101010000011000011101101010100001111011100100011100100001011100011011010011001000000110101100011100011111001100110000001100101111001000100101010111100001001010111001011111110111011011000000001011001010111110110011001100001000101011101111101111110110001100000101110101001001111001001001100000010011010001100011000101110111010011000111000010101110001101110010000000111001011101110101011100001110000101111101100111010100100111110100000001011010100100111001010000010000011111111111100010100010110101111000011000001110011000001111100010100000111010110011101110101001101011100000111100011100100100111101011000001010111100100100111111110001111000000110000111000010001001011011111100001001101101101010000100101101010000011100000011001011110010100011100000001100101010111111010111110011100010110110110111001000101110110011000011000100011100000101111001010000000000101101111110101100001010011100000011011010010101010111001100011000001110100011011010110101111001010001010110110100100111110110111011000010000011100010001000010000110111000011111111100111001100111110111000010110100010100101100100010100011100010000000000000000000000010101110'

EA = EllipticCurve(Fp4, EA_coeffs)
E10 = EllipticCurve(Fp4, E10_coeffs)
E11 = EllipticCurve(Fp4, E11_coeffs)
E1 = E11
S = S1

target = "give me the flag"

prover, verifier = SQISign(), SQISign()

prover.pk = EA

def check_secrets(secrets, E1):
    P, Q, x = secrets
    P = E0(P)
    Q = E0(Q)
    ψ_ker = P + x * Q
    Iψ = kernel_to_ideal(ψ_ker, T_prime)
    assert Iψ.norm() == T_prime, "Iψ has the wrong norm"
    ψ = EllipticCurveIsogenyFactored(E0, ψ_ker, order=T_prime)

    if ψ.codomain() == E1:
        print("FOUND")
        print(f"{x = }")
        return ψ_ker, ψ, Iψ
    # print("Nope")

def compute_phipsi_smooth(msg, ψ_ker, ψ, Iψ, E1):
    ϕ_ker = prover.challenge_from_message(E1, msg.encode())

    ϕ = EllipticCurveIsogenyFactored(E1, ϕ_ker, order=Dc)
    E2 = ϕ.codomain()
    E2.set_order((p**2 - 1) ** 2)

    # Computing IψIϕ
    ψ_dual = dual_isogeny(ψ, ψ_ker, order=T_prime)
    Iϕ_pullback = kernel_to_ideal(ψ_dual(ϕ_ker), Dc)
    IψIϕ = Iψ.intersection(Iϕ_pullback)
    assert IψIϕ.norm() == Iψ.norm() * Iϕ_pullback.norm()

    # Reducing IψIϕ
    IψIϕ_prime = small_equivalent_ideal(IψIϕ)
    IψIϕ_prime, _, _ = EquivalentPrimeIdealHeuristic(IψIϕ_prime)

    # Computing an ideal equivalente to IψIϕ of norm power of l
    IψIϕ_smooth = EquivalentSmoothIdealHeuristic(IψIϕ_prime, l**800)
    print(f"{factor(IψIϕ_smooth.norm()) = }")
    I_trivial = O0.unit_ideal()
    ϕ_trivial = E0.isogeny(E0(0))
    ϕψ_smooth = IdealToIsogenyFromKLPT(
            IψIϕ_smooth, I_trivial, ϕ_trivial, I_prime=IψIϕ_prime
        )
    return ϕψ_smooth, E2

def remove_backtracking(sigma):
    sigma_chain = isogeny_into_blocks(sigma, l)
    curves = [sigma.domain()]
    new_sigmas = []
    for j, fac in enumerate(sigma_chain):
        if j < len(sigma_chain) - 1:
            assert fac.codomain() == sigma_chain[j+1].domain()
        for i, curve in enumerate(curves):
            if fac.codomain().is_isomorphic(curve):
                print(f"{j = }")
                print(f"{i = }")
                print(f"{curve = }")
                new_sigmas = new_sigmas[:i] + [curve.isomorphism_to(fac.codomain())]
                curves = curves[:i+1] + [new_sigmas[-1].codomain()]
                break
        else:
            curves.append(fac.codomain())
            new_sigmas.append(fac)
    final_sigmas = []
    for i in range(len(new_sigmas) - 1):
        final_sigmas.append(new_sigmas[i])
        if not new_sigmas[i].codomain().is_isomorphic(new_sigmas[i+1].domain()):
            print(f"{i = }")
    new_sigma = EllipticCurveHom_composite.from_factors(new_sigmas)
    return new_sigma

# Getting the secret commitment
verifier.verify(EA, (E10, S0), b"Good")
P, Q = torsion_basis(E0, T_prime)
x = randint(1, T_prime)
secrets = (P, Q, x)
hope = check_secrets(secrets, E1)
if hope:
    ψ_ker, ψ, Iψ = hope
else:
    print("Secrets not found :(")
    exit()



print("\nComputing given_phipsi_smooth")
if not os.path.isfile("dumps/given_phipsi_smooth") or (len(sys.argv) > 1 and sys.argv[1] == "new"):
    given_ϕψ_smooth, E2_given = compute_phipsi_smooth("luck", ψ_ker, ψ, Iψ, E1)
    with open("dumps/given_phipsi_smooth", "wb") as f:
        f.write(dumps((given_ϕψ_smooth, E2_given)))
else:
    with open("dumps/given_phipsi_smooth", "rb") as f:
        given_ϕψ_smooth, E2_given = loads(f.read())
print("Done")

print("\nComputing target_phipsi_smooth")
if not os.path.isfile("dumps/target_phipsi_smooth") or (len(sys.argv) > 1 and sys.argv[1] == "new"):
    target_ϕψ_smooth, E2_target = compute_phipsi_smooth(target, ψ_ker, ψ, Iψ, E1)
    with open("dumps/target_phipsi_smooth", "wb") as f:
        f.write(dumps((target_ϕψ_smooth, E2_target)))
else:
    with open("dumps/target_phipsi_smooth", "rb") as f:
        target_ϕψ_smooth, E2_target = loads(f.read())
print("Done")


σ = decompression(EA, E2_given, S, l, f_step_max, e)

def my_dual(phi):
    if is_prime(phi.degree()):
        return phi.dual()
    else:
        return EllipticCurveHom_composite.from_factors([my_dual(x) if x.degree() > 1 else x.codomain().isomorphism_to(x.domain()) for x in phi.factors()[::-1]])

print()
print("Computing composition of isogenies")
if not os.path.isfile("dumps/phi_EA_E0"):
    iso = σ.codomain().isomorphism_to(given_ϕψ_smooth.codomain())
    phi_EA_E0 = my_dual(given_ϕψ_smooth) * iso * σ
    with open("dumps/phi_EA_E0", "wb") as f:
        f.write(dumps(phi_EA_E0))
else:
    with open("dumps/phi_EA_E0", "rb") as f:
        phi_EA_E0 = loads(f.read())
print("Done")
print()

print("Computing final isogeny")
if not os.path.isfile("dumps/final_sigma"):
    final_sigma = target_ϕψ_smooth * phi_EA_E0
    final_sigma = remove_backtracking(final_sigma)
    with open("dumps/final_sigma", "wb") as f:
        f.write(dumps(final_sigma))
else:
    with open("dumps/final_sigma", "rb") as f:
        final_sigma = loads(f.read())
print("Done")
print(f"{factor(final_sigma.degree()) = }")


deg_sigma = factor(final_sigma.degree())[0][1]
print(f"{deg_sigma = }")

if not os.path.isfile("dumps/final_S"):
    final_S = compression(EA, final_sigma, l, f_step_max)
    with open("dumps/final_S", "w") as f:
        f.write(final_S)
else:
    with open("dumps/final_S", "r") as f:
        final_S = f.read()

print(f"{final_S = }")
ϕ_ker = prover.challenge_from_message(E1, target.encode())

assert verifier.verify_response(EA, E1, final_S, ϕ_ker, deg_sigma=deg_sigma)



