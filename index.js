/*
    MIT License

    Copyright (c) 2023 Yvain Ramora

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

/* importing modules */
const argv = require("minimist")(process.argv.slice(2));
const fs = require("fs");

var help = `
Usage: 
    -h                Display the help menu
    -i <filename>     Specify the input file to display decrypted strings
    -d <string>       Decrypt a specific string
    -v                Enable verbose mode
    -l                Display software licensing information
`

if (argv.h) {
    console.log(help);
} else if (argv.l) {
    fs.readFile('LICENSE', 'utf8', (err, data) => {
        if (!err) {
            console.log(data);
        } else {
            console.log('Error:\n    The LICENSE file is missing. Please ensure you have the original, unmodified package.');
        }
    })
} else if (argv.i) {

    /* reading the input file */
    if (fs.existsSync(argv.i)) {
        fs.readFile(argv.i, "utf8", (err, data) => {
            if (!err) {
                decryptString(data);
            } else {
                console.log("Error:\n    An error has occurred while reading the input file.");
            }
        })
    } else {
        console.log("Error:\n    You must provide a valid input file.");
    }
} else if (argv.d) {

} else {
    console.log(help);
}

/* function for finding strings and decrypting them */
function decryptString(data) {

    /* function for extracting encrypted strings in the format `= [ ... ]` */
    function extractCryptedStrings(data) {
        let matchedData = data.match(/=\s*\[.*,.*\]/i);
        if (!matchedData) return [];

        return matchedData[0]
            .replace(/=\s*/, '')
            .split(/\s*,\s*/)
            .filter(str => str.startsWith("'") && str.endsWith("'"))
            .map(str => ConvertEscapeSequences(str.slice(1, -1)));
    }

    /* function to extract strings from a specific function */
    function extractStringsFromFunction(data) {

        /* regex to capture functions returning strings of characters */
        let functionMatch = data.match(/function\s*[0-9A-Z$_]+\s*\(\s*\)\s*{\s*return\s*'.*'\s*}/i);
        if (!functionMatch) return [];

        let stringInsideFunction = functionMatch[0].match(/'.*'/)[0].slice(1, -1);
        return decompress(ConvertEscapeSequences(stringInsideFunction));
    }

    /* function to extract strings corresponding to the format '[0-9A-Z]+' */
    function extractFormattedStrings(data) {
        let matchedStrings = data.match(/'(\\u[0-F]{4}|\\x[0-F]{2}|[0-9A-Z])+'/gi);
        return matchedStrings ? matchedStrings.map(str => ConvertEscapeSequences(str.slice(1, -1))) : [];
    }

    /* finds encrypted strings */
    var functionStrings = extractStringsFromFunction(data);
    var formattedStrings = extractFormattedStrings(data);
    var cryptedStrings = [...new Set(extractCryptedStrings(data).concat(functionStrings, formattedStrings))];

    /* calculates the level of obfuscation */
    var level = levelObfuscation(data);

    /* checks that the obfuscation is JSConfuser */
    if (level != 0) {

        /* decrypts strings based on their signatures */
        cryptedStrings.forEach(str => {
            decrypt(str, level);
        })
    } else {
        console.log("Error:\n    The file is not obfuscated by JSConfuser.");
    }
}

/* function for decrypting a string */
function decrypt(str, level) {
    if (str.startsWith('<~') && str.endsWith('~>')) {
        /*
            Let S be the sequence of characters in the string str
            For each quintuplet of characters Si, Si+1, Si+2, Si+3, Si+4, (where the indices vary in steps of 5), we define:
                C = 52200625 * (Si - 33) + 614125 * (Si+1 - 33) + 7225 * (Si+2 - 33) + 85 * (Si+3 - 33) + (Si+4 - 33)
            where Si represents the ASCII code of the i-th character in the S sequence.
            The following values are extracted from C:
                a = 255 & (C ≫ 24)
                b = 255 & (C ≫ 16)
                c = 255 & (C ≫ 8)
                d = 255 & (C)
            Each quadruplet a, b, c, d is added to the plaintext sequence where:
            ≫ is the right shift operation, & is the bitwise logical "AND" operation.
        */
        var plaintext = [];
        str = str.slice(2, -2).replace(/s/g, '').replace('z', '!!!!!');
        var oldStr = str;
        str += "uuuuu".slice(str.length % 5);
        for (let i = 0; i < str.length; i += 5) {
            var C = 52200625 * (str.charCodeAt(i) - 33) + 614125 * (str.charCodeAt(i + 1) - 33) + 7225 * (str.charCodeAt(i + 2) - 33) + 85 * (str.charCodeAt(i + 3) - 33) + (str.charCodeAt(i + 4) - 33);
            plaintext.push(255 & C >> 24, 255 & C >> 16, 255 & C >> 8, 255 & C);
        }
        plaintext = String.fromCharCode(...plaintext).slice(0, oldStr.length - str.length);
        printResult('<~' + oldStr + '~>', plaintext);
    } else if (str.startsWith('{') && str.endsWith('}')) {
        /*
            let {S1, S2, ..., S2n} be the sequence of numbers extracted from the string str
            For each pair S2i-1, S2i (where 1 ≤ i ≤ n) we define:
                x = S2i-1
                y = S2i
            The decryption process is given by:
                Pi = x ≫ 8 * (y & 7) & 255
            where ≫ is the right shift operation, & is the logical "AND" operation (bit by bit) and Pi is the i-th element of the plaintext sequence.
            The process continues for each pair until all the bits of y have been used, because after each iteration, y is shifted three positions to the right.
        */
        var plaintext = [];
        var oldStr = str;
        str = str.slice(1, -1).split(',').map(Number);
        for (let i = 0; i < str.length; i += 2) {
            var [x, y] = [str[i], str[i + 1]];
            while (y) {
                plaintext.push(x >> 8 * (y & 7) & 255);
                y >>= 3;
            }
        }
        plaintext = String.fromCharCode(...plaintext).replace(/~/g, '');
        printResult('{' + str + '}', plaintext);
    } else {
        var plaintext = [];
        if (level == 1) {
            plaintext = base91Decode(str)
        } else {
            /*
                Let S be the sequence of characters in the string str
                For each character Si (where the indices vary from 0 to length(S) - 1):
                    Zi = Si - 33
                Update x and y as follows:
                    Xi+1 = Xi + 5
                    Yi+1 = (Yi ≪ 5) | Zi
                where ≪ is the left shift operation and ∣ is the logical "OR" operation.
                If, after the update, Xi+1 is equal to or greater than 8:
                    Xi+1 = Xi - 8
                The decryption process is given by:
                    Pi = ((Yi ≪ 5) | Zi) ≫ Xi+1 & 255
                where ≫ is the right shift operation, & is the logical "AND" operation (bit by bit) and Pi is the i-th element of the plaintext sequence.
                The process continues for each character.
            */
            var x = y = 0;
            for (let i = 0; i < str.length; i++) {
                var z = str.charCodeAt(i) - 33;
                x += 5;
                if (x >= 8) {
                    x -= 8;
                    plaintext.push((y << 5 | z) >> x & 255);
                }
                y = y << 5 | z;
            }
        }
        plaintext = String.fromCharCode(...plaintext);
        if (str.length > 2 && plaintext.length > 2) {
            if (entropy(plaintext) < entropy(str)) {
                printResult(str, plaintext);
            } else {
                printResult(entropy(plaintext) < 50 ? plaintext : null, str);
            }
        }
    }
}

/* function to display the results */
function printResult(str, plaintext) {
    if (argv.v) {
        if (str == null) {
            console.log(`
\x1b[90m${'_'.repeat(20)}\x1b[0m
\x1b[90mplaintext  : \x1b[32m'${plaintext}'\x1b[0m
\x1b[90mentropy    : \x1b[33m${entropy(plaintext)}\x1b[0m
\x1b[90m${'_'.repeat(20)}\x1b[0m\n`)
        } else {
            console.log(`
\x1b[90m${'_'.repeat(20)}\x1b[0m
\x1b[90mciphertext : \x1b[32m'${str}'\x1b[0m
\x1b[90mentropy    : \x1b[33m${entropy(str)}\x1b[0m
\x1b[90mplaintext  : \x1b[32m'${plaintext}'\x1b[0m
\x1b[90mentropy    : \x1b[33m${entropy(plaintext)}\x1b[0m
\x1b[90m${'_'.repeat(20)}\x1b[0m\n`)
        }
    } else {
        console.log(plaintext)
    }
}

/* function for converts Unicode and Hexadecimal escape sequences into characters */
function ConvertEscapeSequences(str) {
    var newStr = "";
    var chars = str.match(/(\\x[0-F]{2}|\\u[0-F]{4}|.)/gi);
    if (chars) {
        chars.forEach(char => newStr += char.length != 1 ? String.fromCharCode(parseInt(char.match(/[0-F]+/i)[0], 16)) : char);
    } else {
        newStr = str;
    }
    return newStr;
}

/* function for decompressing JSConfuser strings */
function decompress(str) {
    var firstChar1 = firstChar2 = str[0];
    var byteMax = oldByte = 256;
    var uncompressedChars = [firstChar1];
    var decompressTable = {};
    for (let i = 1; i < str.length; i++) {
        var char = str.charCodeAt(i);
        if (char < byteMax) {
            char = str[i];
        } else {
            char = decompressTable[char] ? decompressTable[char] : firstChar1 + firstChar2;
        }
        uncompressedChars.push(char);
        firstChar2 = char.charAt(0);
        decompressTable[oldByte] = firstChar1 + firstChar2;
        firstChar1 = char;
        oldByte++;
    }
    return uncompressedChars.join('').split('1');
}

/* function for decoding base91 */
function base91Decode(str) {
    var plaintext = [];
    var base91Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
    var currentCharIndex = -1;
    var accumulator = 0;
    var shiftCount = 0;

    for (let i = 0; i < str.length; i++) {
        const charIndex = base91Chars.indexOf(str[i]);

        if (currentCharIndex < 0) {
            currentCharIndex = charIndex;
        } else {
            currentCharIndex += charIndex * base91Chars.length;
            accumulator |= currentCharIndex << shiftCount;
            shiftCount += (currentCharIndex & 8191) > 88 ? 13 : 14;
            while (shiftCount > 7) {
                plaintext.push(accumulator & 255);
                accumulator >>= 8;
                shiftCount -= 8;
            }
            currentCharIndex = -1;
        }
    }
    if (currentCharIndex > -1) {
        plaintext.push((accumulator | currentCharIndex << shiftCount) & 255);
    }
    return plaintext;
}

/* function for calculating the level of obfuscation */
function levelObfuscation(data) {
    let functionMatch = data.match(/function\s*[0-9A-Z$_]+\s*\(\s*[0-9A-Z$_]+\s*,\s*[0-9A-Z$_]+\s*,\s*[0-9A-Z$_]+\s*,\s*[0-9A-Z$_]+\s*=\s*[0-9A-Z$_]+\s*,\s*[0-9A-Z$_]+\s*=\s*[0-9A-Z$_]+\s*\)/gi)
    if (!functionMatch) return 0;
    return functionMatch.length
}

/* function for calculating the entropy of a character string */
function entropy(str) {
    /*
    Let S be a string of length n.
    Let Si be the ith character of S and ord(Si) the ASCII/Unicode value of Si.
    The 'distance' di between two adjacent characters Si and Si+1 is given by :
        di = |ord(Si) - ord(Si+1)|
    The total distance d is the sum of the individual distances:
        d = Σᵢ₌₁ⁿ-¹di
    The entropy E (as we have defined it) is the average of the distances:
        E = D / (n-1)
    */
    str = String(str)
    if (str.length < 2) return 0;
    let totalDistance = 0;
    for (let i = 0; i < str.length - 1; i++) {
        let distance = Math.abs(str.charCodeAt(i) - str.charCodeAt(i + 1));
        totalDistance += distance;
    }
    let averageDistance = totalDistance / (str.length - 1);
    return averageDistance;
}