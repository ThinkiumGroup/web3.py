pragma solidity >=0.4.21;

contract Greeter {
    string public greeting;

    constructor() public  {
        greeting = 'Hello';
    }

    function setGreeting(string memory data) public {
        greeting = data;
    }

    function greet() view public returns (string memory)  {
        return greeting;
    }
}