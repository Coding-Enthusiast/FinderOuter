// Autarkysoft Tests
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using System.Numerics;

namespace Tests
{
    /// <summary>
    /// These are randomly generated keys. Prv1, Pub1,... Prv2, Pub2,... are from the same key pair
    /// </summary>
    public static class KeyHelper
    {
        private static readonly byte[] _order = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337").ToByteArray(true, true);
        public static byte[] CurveOrder => _order;


        internal static string Prv1Wif = "L28Peud5cQcijrtMthAdUS8FynpM8PKZtnoUZb1VAio9WxKoebHt";
        internal static PrivateKey Prv1 => new(Prv1Wif);
        internal static Point Pub1
        {
            get
            {
                Point.TryRead(Pub1UnCompBytes, out Point result);
                return result;
            }
        }
        internal static string Pub1CompHex => "030b3ad1cea48c61bdcff356675d92010290cdc2e04e1c9e68b6a01d3cec746c17";
        internal static string Pub1UnCompHex => "040b3ad1cea48c61bdcff356675d92010290cdc2e04e1c9e68b6a01d3cec746c17b95aedf5242b50b5c82147697351941032602332d5cc81531eec98a9b8f9c7cd";
        internal static byte[] Pub1CompBytes => Helper.HexToBytes(Pub1CompHex);
        internal static byte[] Pub1UnCompBytes => Helper.HexToBytes(Pub1UnCompHex);
        internal static string Pub1CompHashHex => "2145a147db08e8defb15dbfcb9968971e98b0128";
        internal static string Pub1UnCompHashHex => "b716d8e4a05af9161dcaf0d62ce87475c863ef72";
        internal static byte[] Pub1CompHash => Helper.HexToBytes(Pub1CompHashHex);
        internal static byte[] Pub1UnCompHash => Helper.HexToBytes(Pub1UnCompHashHex);
        internal static string Pub1CompAddr => "142viJrTYHA4TzryiEiuQkYk4Ay5TfpzqW";
        internal static string Pub1UnCompAddr => "1Hh62ZRFLpWT92EKpCbjFc1UgrGDNtfx4i";
        internal static string Pub1BechAddr => "bc1qy9z6z37mpr5da7c4m07tn95fw85ckqfg28wxzd";
        internal static string Pub1BechAddrUncomp => "bc1qkutd3e9qttu3v8w27rtze6r5whyx8mmjvgxhjc";
        internal static string Pub1BechAddrHex => "2145a147db08e8defb15dbfcb9968971e98b0128";
        internal static string Pub1BechAddrHexUncomp => "b716d8e4a05af9161dcaf0d62ce87475c863ef72";
        internal static string Pub1NestedSegwit => "39vipRmsscHCg3sT7FHfqSUmCoNZroCygq";
        internal static string Pub1NestedSegwitHex => "5a588d0320647b22b6b70ad345dbfbc488380cf0";
        internal static string Pub1NestedSegwitUncomp => "3FKpsaDGW6CnAn3eotAefJL12z6u5ihp8P";
        internal static string Pub1NestedSegwitUncompHex => "958fccf9de503092f161d7432890574aef62a965";
        internal static string Msg1ToSign => "The quick brown fox jumps over the lazy dog";
        /// <summary>
        /// Signature r and s without the starting byte (recId)
        /// </summary>
        internal static string Msg1Sig => "4125023df3abc0cbf0bdf5edcd1b1055834e9477ae89d5c54fb002e74e2529644c50c6b30c1cf2b5d35b2679844f25736bf5b7eefd4b83db70e451b537402e6b";

        internal static string VerifiableDataToSign => "d2f695caacb36e93e5f8f9db4d2b74c9ea6f4a3dbb23ca245401eaaa8eabb07e";
        internal static string VerifiableSignature1 => "3045022100a62707bee4f57823844b6401f1acc655f5d1008c2d1cc256b82dd4e4c39406d0022037fe2afbc588e06f7e7523010b9f321a53b240c63af370fa139d953dd4e1d94101";



        internal static PrivateKey Prv2 => new("KxWSVSkSv3gGs2AmCF3qRCc6MqAikTL3n4wwMJjsfQikMU61ZQkL");
        internal static Point Pub2
        {
            get
            {
                Point.TryRead(Pub2UnCompBytes, out Point result);
                return result;
            }
        }
        internal static string Pub2CompHex => "036c9e91206e3e3618f45f60a92a2a48670beb46d8d39b69290eec467b521ae591";
        internal static string Pub2UnCompHex => "046c9e91206e3e3618f45f60a92a2a48670beb46d8d39b69290eec467b521ae591059e4f371c885229be97b0b23e8ebab6e603465fb3618b05697d6225142656e5";
        internal static byte[] Pub2CompBytes => Helper.HexToBytes(Pub2CompHex);
        internal static byte[] Pub2UnCompBytes => Helper.HexToBytes(Pub2UnCompHex);
        internal static byte[] Pub2CompHash => Helper.HexToBytes("8f634c80a4e9c9619d4856e94de014c538fadaa3");
        internal static byte[] Pub2UnCompHash => Helper.HexToBytes("95c2a85c042ae21e167df5f3382eaa256dd42ee7");
        internal static string Pub2CompAddr => "1E5AaqVBxLbbAokPA9VpjZNsWtH1hbBfcS";
        internal static string Pub2UnCompAddr => "1Eersdkb2p2jPj4kZ2cEQihgHPr57WWqrC";
        internal static string Pub2BechAddr => "bc1q3a35eq9ya8ykr82g2m55mcq5c5u04k4rvdeav8";
        internal static string Pub2NestedSegwit => "3HuNV2HoYAdUspE7utaXQoTgHvR5Fk33f2";
        internal static string Pub2NestedSegwitHex => "b1d82aac8ec0d0f0841547bdfbce08a80826bc96";

        internal static string VerifiableSignature2 => "3045022100ea759d88b199b7ccb4cfe5e15c878816d5663ee6f50621419f8c6e7c6b002c7102207727cb77ed15ce49beba2969fb358b0e9811f19c713a1c369c750f80ef60d49d01";



        internal static PrivateKey Prv3 => new("KwToaM89oezgBF1TNjws2BC6Uo7nt57iWkFeqZQGibLBLgoYy2QT");
        internal static Point Pub3
        {
            get
            {
                Point.TryRead(Pub3UnCompBytes, out Point result);
                return result;
            }
        }
        internal static string Pub3CompHex => "020c347b1b571244a32895604f593bfffc2bad4689488bfaed8048c7a116b13604";
        internal static string Pub3UnCompHex => "040c347b1b571244a32895604f593bfffc2bad4689488bfaed8048c7a116b13604c604ade728f0824b6ec409f8264a2b6205021f89eefa71a1106d44b06ea92024";
        internal static byte[] Pub3CompBytes => Helper.HexToBytes(Pub3CompHex);
        internal static byte[] Pub3UnCompBytes => Helper.HexToBytes(Pub3UnCompHex);
        internal static byte[] Pub3CompHash => Helper.HexToBytes("65dd8f5cfe404d6919f53de4f9fa91378cfb17c6");
        internal static byte[] Pub3UnCompHash => Helper.HexToBytes("d3deb65141b9a889f3bf9c451ce18987b017ba56");
        internal static string Pub3CompAddr => "1AHcfdoEvJodDUMsBFynie9qZbyHbissox";
        internal static string Pub3UnCompAddr => "1LKGNnoAfau62HpKYbTwQ89c6MHHCBbtVm";
        internal static string Pub3BechAddr => "bc1qvhwc7h87gpxkjx048hj0n753x7x0k97xue29t8";
        internal static string Pub3NestedSegwit => "32HGWhsh8oUCReuBs7HHFtNtf7LktbHrjv";
        internal static string Pub3NestedSegwitHex => "067a522bdae6b12e7a45fa816fd388a2af4744c0";

        internal static string VerifiableSignature3 => "304402203ed6e9d41a3f66478266616eaa0eb565afebc7596005de9bf0cca09f56f5784402204702a3010158d7771a06525285a727b1e06844b5bb5e3d6c94f25d1827eee4a201";
    }
}
