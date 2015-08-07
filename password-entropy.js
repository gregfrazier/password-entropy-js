// Checks password complexity and entropy
function CheckEntropySpaceDepth(pass){
    var bits = 0,
        lowerCase = /[a-z]+/g,
        upperCase = /[A-Z]+/g,
        numeric   = /[0-9]+/g,
        extra     = /([^a-zA-Z0-9])+/g; 
    bits = (lowerCase.test(pass) ? 26 : 0)
         + (upperCase.test(pass) ? 26 : 0)
         + (numeric.test(pass)   ? 10 : 0)
         + (extra.test(pass)     ? 33 : 0);
    return { entropy: Math.round(pass.length * Math.log(bits) / Math.log(2)), spacedepth: bits };
}

function CheckStrength(pass){
    var strength = 0,
        EntDepth = CheckEntropySpaceDepth(pass);
    
    // This calculates the count of all possible combinations
    var SearchSpaceSize = function(spacedepth, len){
        return len == 0 ? 0 : SearchSpaceSize(spacedepth, len-1) + Math.pow(spacedepth, len);
    };

    // Assumes 100 billion guesses a second, and calculates how many years to crack.
    var SpaceStrength = SearchSpaceSize(EntDepth.spacedepth, pass.length) / Math.pow(10,11) / 60 / 60 / 24 / 365;

    // Assumes not susceptible to dictionary attack
    strength += (function(arr, val){
        var r = 0, x = 0;
        for(; x < arr.length; r = val > arr[x] ? x : r, x++);
        return r;
    })([0,5,100,1000], SpaceStrength);
    // Bits of Entropy, a higher number means higher unpredictability
    strength += (function(arr, val){
        var r = 0, x = 0;
        for(; x < arr.length; r = val > arr[x++] ? x : r);
        return r;
    })([0,48,85,128], EntDepth.entropy);
    
    return strength; // out of possible 7.
}