


**0-days Vulnerabilities in XNU IOKIT** 
>AppleARMSMP

**Lack of error handling for calls to `IOService::waitForMatchingService, IOService::getProperty, IOService::registerInterrupt, and IOService::enableInterrupt`**.

*Description:* These functions can fail for various reasons, such as if the device or interrupt being looked up or registered does not exist, or if there is a problem with the arguments being passed. If the code does not check the return values of these functions and handle any errors that occur, it could lead to unexpected behavior or crashes.

*Impact:* An attacker could potentially trigger errors in these functions to cause the system to behave in unexpected ways, potentially leading to a denial of service or other vulnerabilities.

Example:
```
IOReturn ret;

ret = someIOService->getProperty(someProperty, &someValue);
if (kIOReturnSuccess != ret) {
    // handle error
}
```

**Unvalidated input for `ipi_handler` and `pmi_handler` functions passed to `IOService::registerInterrupt`.**

*Description:* These functions are passed as arguments to `IOService::registerInterrupt` without any validation. An attacker could potentially provide malicious functions that could be used to execute arbitrary code with kernel privileges.

*Impact:* An attacker could potentially provide malicious input for these functions to execute arbitrary code with kernel privileges.

Example:

```
// Ensure that the function being passed as an argument is a legitimate handler
if (!is_legitimate_handler_function(ipi_handler)) {
    // do not register the handler
} else {
    someIOService->registerInterrupt(someIndex, someTarget, (IOInterruptAction)ipi_handler, someRefCon);
}
```

**Use of global variables that can be modified by an attacker.**

*Description:* The code uses global variables that are initialized at runtime, including `gCPUIC,` `gPMGR,` `gAIC,` and `topology_info.` If an attacker can modify the values of these variables, they could potentially cause the system to behave in unexpected ways or crash.
