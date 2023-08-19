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

/* reading the input file */
if (argv.i) {
    if (fs.existsSync(argv.i)) {
        fs.readFile(argv.i, "utf8", (err, data) => {
            if (!err) {
                decryptString(data);
            } else {
                console.log("\x1b[31mError: An error has occurred while reading the input file.\x1b[0m");
            }
        })
    } else {
        console.log("\x1b[31mError: You must provide a valid input file.\x1b[0m");
    }
} else {
    console.log("\x1b[31mError: You need to provide an input file!\n\x1b[33mexample: node index.js -i obfuscated.js\x1b[0m");
}

/* function for finding strings and decrypting them */
function decryptString(data) {

    /* finds encrypted strings */
    var cryptedStrings = data.match(/=\s*\[.*,.*\]/i)[0].replace(/=\s*/, '').split(/\s*,\s*/g).filter(str => str.startsWith("'") && str.endsWith("'")).map(str => ConvertEscapeSequences(str.slice(1, -1))).concat(decompress(ConvertEscapeSequences(data.match(/function\s*[0-9A-Z$_]+\s*\(\s*\)\s*{\s*return\s*'.*'\s*}/i)[0].match(/'.*'/)[0].slice(1, -1))));

    /* decrypts strings based on their signatures */
    cryptedStrings.forEach(str => {
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
            console.log('\x1b[90m\'<~' + oldStr + '~>\'\x1b[0m -> \x1b[90m(plaintext entropy : \x1b[33m' + entropy(plaintext) + '\x1b[90m)\x1b[0m -> \x1b[32m\'' + plaintext + '\'\x1b[0m');
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
            console.log('\x1b[90m\'' + oldStr + '\'\x1b[0m -> \x1b[90m(plaintext entropy : \x1b[33m' + entropy(plaintext) + '\x1b[90m)\x1b[0m -> \x1b[32m\'' + plaintext + '\'\x1b[0m');
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
            var plaintext = [];
            var x = y = 0;
            for(let i = 0; i < str.length; i++) {
                var z = str.charCodeAt(i) - 33;
                x += 5;
                if(x >= 8){
                    x -=8;
                    plaintext.push((y << 5 | z) >> x & 255);
                }
                y = y << 5 | z;
            }
            var average = plaintext.reduce((acc, val) => acc + val, 0) / plaintext.length;
            plaintext = String.fromCharCode(...plaintext);
            if(average >= 49 && average <= 122) {
                console.log('\x1b[90m\'' + str + '\'\x1b[0m -> \x1b[90m(plaintext entropy : \x1b[33m' + entropy(plaintext) + '\x1b[90m)\x1b[0m -> \x1b[32m\'' + plaintext + '\'\x1b[0m');
            }else{
                console.log('\x1b[90m\'' + plaintext + '\'\x1b[0m -> \x1b[90m(plaintext entropy : \x1b[33m' + entropy(str) + '\x1b[90m)\x1b[0m -> \x1b[32m\'' + str + '\'\x1b[0m');
            }
        }
    })
}

/* function for converts Unicode and Hexadecimal escape sequences into characters */
function ConvertEscapeSequences(str) {
    var newStr = "";
    var chars = str.match(/(\\x[0-F]{2}|\\u[0-F]{4}|.)/gi);
    if (chars) {
        chars.forEach(char => newStr += char.length != 1 ? String.fromCharCode(parseInt(char.match(/[0-F]+/i)[0], 16)) : char);
    } else {
        newStr = str
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

/* function for calculating the entropy of a character string */
function entropy(str) {
    /*
        The formula for the entropy H of a chain X is:
            H(X) = -Σᵢ₌₁ⁿp(Xi)*log2(p(Xi))
        where p(Xi) is the probability of element Xi appearing in the string.
    */
    if (str.length === 0) return 0;
    const occurrenceMap = {};
    for (let char of str) {
        if (occurrenceMap[char]) {
            occurrenceMap[char]++;
        } else {
            occurrenceMap[char] = 1;
        }
    }
    let entropy = 0;
    for (let key in occurrenceMap) {
        const probability = occurrenceMap[key] / str.length;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}