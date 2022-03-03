// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using Autarkysoft.Bitcoin.Cryptography.Hashing;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Models;
using System;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class MessageSignatureService
    {
        public MessageSignatureService(IReport rep)
        {
            calc = new EllipticCurveCalculator();
            inputService = new InputService();
            report = rep;
        }


        private readonly IReport report;
        private readonly EllipticCurveCalculator calc;
        private readonly InputService inputService;


        private static Signature CreateFromRecId(byte[] sigBa)
        {
            if (!Signature.TryReadWithRecId(sigBa, out Signature result, out string error))
            {
                throw new FormatException(error);
            }

            return result;
        }

        private static bool CheckAddress(string addr, out AddressType addrType)
        {
            addrType = Address.GetAddressType(addr, NetworkType.MainNet);

            return addrType != AddressType.Unknown &&
                   addrType != AddressType.Invalid &&
                   addrType != AddressType.P2WSH &&
                   addrType != AddressType.P2TR;
        }

        private static bool CheckMessage(string message, out byte[] toSign)
        {
            try
            {
                FastStream stream = new();
                byte[] msgBa = Encoding.UTF8.GetBytes(message);
                stream.Write((byte)Constants.MsgSignConst.Length);
                stream.Write(Encoding.UTF8.GetBytes(Constants.MsgSignConst));
                new CompactInt((ulong)msgBa.Length).WriteToStream(stream);
                stream.Write(msgBa);

                using Sha256 hash = new();
                toSign = hash.ComputeHashTwice(stream.ToByteArray());

                return true;
            }
            catch (Exception)
            {
                toSign = null;
                return false;
            }
        }

        private static bool CheckSignature(string sig, out byte[] sigBa)
        {
            try
            {
                sigBa = Convert.FromBase64String(sig);
                return true;
            }
            catch (Exception)
            {
                sigBa = null;
                return false;
            }
        }

        private bool CheckPubkeys(Signature sig, byte[] toSign, string address, AddressType addrType)
        {
            if (calc.TryRecoverPublicKeys(toSign, sig, out EllipticCurvePoint[] pubkeys))
            {
                foreach (EllipticCurvePoint pt in pubkeys)
                {
                    PublicKey pub = new(pt);

                    if (addrType == AddressType.P2PKH)
                    {
                        if (Address.GetP2pkh(pub, true) == address)
                        {
                            report.AddMessageSafe("Signature is valid (address type is compressed P2PKH).");
                            return true;
                        }
                        else if (Address.GetP2pkh(pub, false) == address)
                        {
                            report.AddMessageSafe("Signature is valid (address type is uncompressed P2PKH).");
                            return true;
                        }
                    }
                    else if (addrType == AddressType.P2SH)
                    {
                        if (Address.GetP2sh_P2wpkh(pub) == address)
                        {
                            report.AddMessageSafe("Signature is valid (address type is nested SegWit).");
                            return true;
                        }
                    }
                    else if (addrType == AddressType.P2WPKH)
                    {
                        if (Address.GetP2wpkh(pub) == address)
                        {
                            report.AddMessageSafe("Signature is valid (address type is compressed P2WPKH).");
                            return true;
                        }
                    }
                    else
                    {
                        report.AddMessageSafe("Unexpected address type.");
                        return false;
                    }
                }

                report.AddMessageSafe($"Found {pubkeys.Length} public keys but none of them return the given address.");
                return false;
            }
            else
            {
                report.AddMessageSafe("Could not recover any public keys.");
                return false;
            }
        }


        public bool Validate(string message, string address, string signature)
        {
            report.Init();

            if (inputService.NormalizeNFKD(message, out string norm))
            {
                message = norm;
                report.AddMessage("Input message was normalized using Unicode Normalization Form Compatibility Decomposition.");
            }

            if (!CheckMessage(message, out byte[] toSign))
                return report.Fail("Invalid message UTF8 format.");
            if (!CheckAddress(address, out AddressType addrType))
            {
                if (addrType == AddressType.P2WSH)
                {
                    report.Fail("Signature verification is not defined for P2WSH address types.");
                }
                else if (addrType == AddressType.P2TR)
                {
                    report.Fail("Signature verification is not defined for P2TR address types.");
                }
                else
                {
                    report.Fail("Invalid address format.");
                }

                return false;
            }

            if (!CheckSignature(signature, out byte[] sigBa))
                return report.Fail("Invalid signature base-64 format.");
            if (sigBa.Length != 1 + 32 + 32) // 65 bytes
                return report.Fail($"Invalid signature length (it must be 65 bytes, it is {sigBa.Length} bytes instead).");

            Signature sig = CreateFromRecId(sigBa);
            bool success = CheckPubkeys(sig, toSign, address, addrType);
            return report.Finalize(success);
        }



        private bool ChangeSigAndCheck(string message, string address, AddressType addrType, byte[] sigBa)
        {
            CheckMessage(message, out byte[] toSign);

            if (sigBa.Length > 65 /*1 + 32 + 32*/ && sigBa.Length <= 67 /*1 + 32 + 32 + 1 + 1*/)
            {
                // This is case is when most significant bit of each integer was set 
                // so an additioan 0 was added by mistake (similar to DER encoding for tx signatures).
                BigInteger r;
                BigInteger s;
                // <recid> 0 <32> 0 <32> 
                if (sigBa.Length == 67)
                {
                    if (sigBa[1] == 0 && sigBa[34] == 0)
                    {
                        r = sigBa.SubArray(2, 32).ToBigInt(true, true);
                        s = sigBa.SubArray(35, 32).ToBigInt(true, true);
                    }
                    else if (sigBa[33] == 0 && sigBa[66] == 0)
                    {
                        r = sigBa.SubArray(2, 32).ToBigInt(false, true);
                        s = sigBa.SubArray(35, 32).ToBigInt(false, true);
                    }
                    else
                    {
                        report.AddMessageSafe("Both r and s values are too big to be valid.");
                        return false;
                    }
                }
                // Now check cases where only r or s is 33 bytes (that is sigBa.Length == 66)
                // <recid> 0 <32> <32>  OR  <recid> <32> 0 <32> 
                else if (sigBa[1] == 0)
                {
                    r = sigBa.SubArray(2, 32).ToBigInt(true, true);
                    s = sigBa.SubArray(34, 32).ToBigInt(true, true);
                }
                else if (sigBa[33] == 0)
                {
                    // This 0 is either for s in big-endian or for r in little-endian
                    // 1. big-endian padded s
                    r = sigBa.SubArray(1, 32).ToBigInt(true, true);
                    s = sigBa.SubArray(34, 32).ToBigInt(true, true);
                    Signature temp = new(r, s, sigBa[0]);
                    if (CheckPubkeys(temp, toSign, address, addrType))
                    {
                        report.AddMessageSafe($"Modified signature is: {temp.ToByteArrayWithRecId().ToBase64()}");
                        return true;
                    }

                    // 2. little-endian padded 3
                    r = sigBa.SubArray(1, 32).ToBigInt(false, true);
                    s = sigBa.SubArray(34, 32).ToBigInt(false, true);
                }
                else if (sigBa[65] == 0)
                {
                    r = sigBa.SubArray(1, 32).ToBigInt(false, true);
                    s = sigBa.SubArray(33, 32).ToBigInt(false, true);
                }
                else
                {
                    report.AddMessageSafe("Either r or s value is too big to be valid.");
                    return false;
                }

                Signature sig = new(r, s, sigBa[0]);
                return CheckPubkeys(sig, toSign, address, addrType);
            }
            if (sigBa.Length == 1 + 32 + 32)
            {
                report.AddMessageSafe("Checking with original signature.");
                Signature sig = CreateFromRecId(sigBa);
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    return true;
                }

                report.AddMessageSafe("Using little-endian when converting bytes to r and s.");
                byte[] rBa = sigBa.SubArray(1, 32);
                byte[] sBa = sigBa.SubArray(33, 32);

                sig = new Signature(rBa.ToBigInt(false, true), sBa.ToBigInt(false, true), sigBa[0]);
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    report.AddMessageSafe($"Modified signature is: {sig.ToByteArrayWithRecId().ToBase64()}");
                }
                else
                {
                    return false;
                }
            }
            else if (sigBa.Length == 32 + 32)
            {
                report.AddMessageSafe("Signature length is shorter than 65 bytes.");
                report.AddMessageSafe("Adding an initial byte in place of missing recovery ID.");
                Signature sig = CreateFromRecId(sigBa.AppendToBeginning(0));
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    report.AddMessageSafe($"Modified signature is: {sig.ToByteArrayWithRecId().ToBase64()}");
                    return true;
                }

                report.AddMessageSafe("Assume first byte is recovery ID and integers were shorter than 32 bytes.");
                report.AddMessageSafe("Checking shorter r");
                byte[] rBa = sigBa.SubArray(1, 31);
                byte[] sBa = sigBa.SubArray(32, 32);

                sig = new Signature(rBa.ToBigInt(true, true), sBa.ToBigInt(true, true), sigBa[0]);
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    report.AddMessageSafe($"Modified signature is: {sig.ToByteArrayWithRecId().ToBase64()}");
                    return true;
                }

                report.AddMessageSafe("Checking shorter r (little-endian)");
                sig = new Signature(rBa.ToBigInt(false, true), sBa.ToBigInt(false, true), sigBa[0]);
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    report.AddMessageSafe($"Modified signature is: {sig.ToByteArrayWithRecId().ToBase64()}");
                    return true;
                }

                report.AddMessageSafe("Checking shorter s");
                rBa = sigBa.SubArray(1, 32);
                sBa = sigBa.SubArray(33, 31);

                sig = new Signature(rBa.ToBigInt(true, true), sBa.ToBigInt(true, true), sigBa[0]);
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    report.AddMessageSafe($"Modified signature is: {sig.ToByteArrayWithRecId().ToBase64()}");
                    return true;
                }

                report.AddMessageSafe("Checking shorter s (little-endian)");
                sig = new Signature(rBa.ToBigInt(false, true), sBa.ToBigInt(false, true), sigBa[0]);
                if (CheckPubkeys(sig, toSign, address, addrType))
                {
                    report.AddMessageSafe($"Modified signature is: {sig.ToByteArrayWithRecId().ToBase64()}");
                    return true;
                }
            }

            return false;
        }

        public async Task<bool> TryFindProblem(string message, string address, string signature)
        {
            report.Init();

            if (inputService.NormalizeNFKD(message, out string norm))
            {
                message = norm;
                report.AddMessage("Input message was normalized using Unicode Normalization Form Compatibility Decomposition.");
            }
            if (!CheckMessage(message, out _) ||
                !CheckAddress(address, out AddressType addrType) ||
                !CheckSignature(signature, out byte[] sigBa))
            {
                return report.Fail("Input formats are bad, Noting can be done.");
            }

            bool success = await Task.Run(() =>
            {
                if (message.Contains("\r\n"))
                {
                    report.AddMessageSafe("The original message contains new lines. " +
                        "The byte value of each new line was changed from \"\\r\\n\" to \"\\n\".");

                    report.AddMessageSafe("Checking with modified message.");
                    if (ChangeSigAndCheck(message.Replace("\r\n", "\n"), address, addrType, sigBa))
                    {
                        return true;
                    }

                    report.AddMessageSafe("The problem doesn't seem to be the message. Continue with original message.");
                }

                return ChangeSigAndCheck(message, address, addrType, sigBa);
            }
            );

            return report.Finalize(success);
        }
    }
}
