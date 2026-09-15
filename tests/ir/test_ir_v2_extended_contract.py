from fwmigrate.ir import (
    IREndpointContextProvider,
    IRProxyAddress,
    IRProxyRequestMatch,
    IRWebProxy,
    IRWebProxySettings,
    IRZTNAProvider,
)


def test_legacy_proxy_and_endpoint_python_names_are_aliases():
    assert IRProxyAddress is IRProxyRequestMatch
    assert IRWebProxySettings is IRWebProxy
    assert IRZTNAProvider is IREndpointContextProvider
