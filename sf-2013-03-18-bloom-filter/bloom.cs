using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

public interface IStringHash
{
    UInt32 Hash (string str);
}

public class StandardHash : IStringHash
{
    public UInt32 Hash (string str)
    {
	return (UInt32) str.GetHashCode ();
    }
}

// http://landman-code.blogspot.com/2009/02/c-superfasthash-and-murmurhash2.html
public class MurmurHash2Simple : IStringHash
{
    public UInt32 Hash (string str)
    {
	return Hash (System.Text.Encoding.UTF8.GetBytes(str));
    }

    public static UInt32 Hash(Byte[] data)
    {
	return Hash(data, 0xc58f1a7b);
    }
    const UInt32 m = 0x5bd1e995;
    const Int32 r = 24;

    static UInt32 Hash(Byte[] data, UInt32 seed)
    {
	Int32 length = data.Length;
	if (length == 0)
	    return 0;
	UInt32 h = seed ^ (UInt32)length;
	Int32 currentIndex = 0;
	while (length >= 4)
	{
	    UInt32 k = BitConverter.ToUInt32(data, currentIndex);
	    k *= m;
	    k ^= k >> r;
	    k *= m;

	    h *= m;
	    h ^= k;
	    currentIndex += 4;
	    length -= 4;
	}
	switch (length)
	{
	    case 3:
		h ^= BitConverter.ToUInt16(data, currentIndex);
		h ^= (UInt32)data[currentIndex + 2] << 16;
		h *= m;
		break;
	    case 2:
		h ^= BitConverter.ToUInt16(data, currentIndex);
		h *= m;
		break;
	    case 1:
		h ^= data[currentIndex];
		h *= m;
		break;
	    default:
		break;
	}

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
    }
}

public class SuperFastHashSimple : IStringHash
{
    public UInt32 Hash (string str)
    {
	return Hash (System.Text.Encoding.UTF8.GetBytes(str));
    }

    UInt32 Hash(Byte[] dataToHash)
    {
	Int32 dataLength = dataToHash.Length;
	if (dataLength == 0)
	    return 0;
	UInt32 hash = Convert.ToUInt32(dataLength);
	Int32 remainingBytes = dataLength & 3; // mod 4
	Int32 numberOfLoops = dataLength >> 2; // div 4
	Int32 currentIndex = 0;
	while (numberOfLoops > 0)
	{
	    hash += BitConverter.ToUInt16(dataToHash, currentIndex);
	    UInt32 tmp = (UInt32)(BitConverter.ToUInt16(dataToHash, currentIndex + 2) << 11) ^ hash;
	    hash = (hash << 16) ^ tmp;
	    hash += hash >> 11;
	    currentIndex += 4;
	    numberOfLoops--;
	}

	switch (remainingBytes)
	{
	    case 3: hash += BitConverter.ToUInt16(dataToHash, currentIndex);
		hash ^= hash << 16;
		hash ^= ((UInt32)dataToHash[currentIndex + 2]) << 18;
		hash += hash >> 11;
		break;
	    case 2: hash += BitConverter.ToUInt16(dataToHash, currentIndex);
		hash ^= hash << 11;
		hash += hash >> 17;
		break;
	    case 1: hash += dataToHash[currentIndex];
		hash ^= hash << 10;
		hash += hash >> 1;
		break;
	    default:
		break;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
    }
}

// http://blogs.msdn.com/b/csharpfaq/archive/2006/10/09/how-do-i-calculate-a-md5-hash-from-a-string_3f00_.aspx
public class CryptographicHash : IStringHash
{
    HashAlgorithm ha;

    public CryptographicHash (HashAlgorithm _ha)
    {
	ha = _ha;
    }

    public UInt32 Hash (string input)
    {
	byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
	byte[] hash = ha.ComputeHash(inputBytes);
	return MurmurHash2Simple.Hash (hash);
    }
}

public class BloomFilter
{
    IStringHash[] hashes;
    BitArray table;

    public BloomFilter (int size, IEnumerable<IStringHash> _hashes)
    {
	hashes = _hashes.ToArray ();
	table = new BitArray (size);
    }

    public void Add (string str)
    {
	foreach (var hash in hashes)
	{
	    var h = hash.Hash (str) % table.Length;
	    table.Set ((int)h, true);
	}
    }

    public bool Lookup (string str)
    {
	foreach (var hash in hashes)
	{
	    var h = hash.Hash (str) % table.Length;
	    if (!table.Get ((int)h))
		return false;
	}
	return true;
    }

    public float Occupancy ()
    {
	int occupied = 0;
	for (int i = 0; i < table.Length; ++i)
	{
	    if (table.Get (i))
		++occupied;
	}
	return (float)occupied / (float)table.Length;
    }
}

public class BloomTest
{
    public static int Main ()
    {
	var hashes = new IStringHash[] { new StandardHash (),
					 new MurmurHash2Simple (),
					 new SuperFastHashSimple (),
					 /*
					 new CryptographicHash (MD5.Create ()),
					 new CryptographicHash (SHA1.Create ()),
					 new CryptographicHash (RIPEMD160Managed.Create ()),
					 new CryptographicHash (MACTripleDES.Create ())
					 */ };
	var bloom = new BloomFilter (1000003, hashes);
	var positive = new List<string> ();
	var negative = new List<string> ();
	var toggle = true;
	foreach (var line in File.ReadAllLines ("/usr/share/dict/words"))
	{
	    var l = line.Trim ();
	    if (toggle)
	    {
		positive.Add (l);
		bloom.Add (l);
	    }
	    else
	    {
		negative.Add (l);
	    }
	    toggle = !toggle;
	}

	Console.WriteLine ("occupancy for " + positive.Count + " words: " + bloom.Occupancy ());

	foreach (var line in positive)
	{
	    if (!bloom.Lookup (line))
	    {
		Console.WriteLine ("error!");
		return 1;
	    }
	}

	int false_positives = 0;
	foreach (var line in negative)
	{
	    if (bloom.Lookup (line))
		++false_positives;
	}

	Console.WriteLine ("false positives: " + ((float)false_positives / negative.Count));

	return 0;
    }
}
