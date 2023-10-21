// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services;

namespace Tests.Services
{
    public class AddressServiceTests
    {
        [Fact]
        public void GetAllAddressesTest()
        {
            string actual = AddressService.GetAllAddresses(KeyHelper.Pub1);
            Assert.Contains(KeyHelper.Pub1CompAddr, actual);
            Assert.Contains(KeyHelper.Pub1UnCompAddr, actual);
            Assert.Contains(KeyHelper.Pub1BechAddr, actual);
            Assert.Contains(KeyHelper.Pub1NestedSegwit, actual);
        }
    }
}
