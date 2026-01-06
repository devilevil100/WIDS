// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract DigitalNotebook {
    
    struct Note {
        string message;
        uint256 timestamp;
    }

    mapping(address => Note[]) public userNotes;

    uint256 public totalNotes = 0;
 
    function addNote(string memory _message) public {
        Note memory newNote = Note({
            message: _message,
            timestamp: block.timestamp
        });
        
        userNotes[msg.sender].push(newNote);
        
        totalNotes++;
    }
    
    function getNotes() public view returns (Note[] memory) {
        return userNotes[msg.sender];
    }
    
    function getMyNoteCount() public view returns (uint256) {
        return userNotes[msg.sender].length;
    }
}
