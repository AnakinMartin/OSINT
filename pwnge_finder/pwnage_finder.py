import requests
import json
import itertools
import time
import argparse


USER_AGENT = ("Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 "
			  "Firefox/5.0.1")


def account_creator(file_user_names, file_user_surnames, file_email_domains):

    user_names = []
    user_surnames = []
    email_domains = []

    # Load user names from file.
    with open(file_user_names) as file_user_names:
        user_names = file_user_names.read().splitlines()
    # Load user surnames from file.
    with open (file_user_surnames) as file_user_surnames:
        user_surnames = file_user_surnames.read().splitlines()
    # Load email domains from file.
    with open(file_email_domains) as file_email_domains:
        email_domains = file_email_domains.read().splitlines()

    accounts = []

    for account in itertools.product(user_names, user_surnames, email_domains):

        account = list(account)

        # Format middle and multiple worded names.
        for i, item in enumerate(account):
            if ' ' in item:
                item = item.replace(" ", "")
                account[i] = item

        # Format 'johndoe@example.com'.
        account_namesurname = ''.join(account).lower()

        # Format 'jdoe@example.com'.
        account_initialsurname = ("{name}{surname}{domain}"
                                  .format(name=account[0][0], 
                                          surname=account[1], 
                                          domain=account[2]).lower())

        # Format 'john.doe@example.com'.
        account_namedotsurname = ("{name}.{surname}{domain}"
                                  .format(name=account[0], 
                                          surname=account[1], 
                                          domain=account[2]).lower())

        # TODO: Improve middle and multiple worded name parsing.

        accounts.extend([account_namesurname, 
                         account_initialsurname, 
                         account_namedotsurname])

    return sorted(set(accounts))


def haveibeenpwned(accounts, pwned_accounts, headers):

    print("--------------")
    print("HAVEIBEENPWNED")
    print("--------------")

    for account in accounts:

        print (account)

        # Wait for the 'no abuse' time.
        time.sleep(1.5)
        resp = requests.get(url="https://haveibeenpwned.com/api/v2"
                                "/breachedaccount/{account}"
                                "?truncateResponse=true"
                                .format(account=account), headers=headers)

        leaks_list = []

        if resp.status_code == 200 and resp.json() is not None:

            pwnage_json = resp.json()

            del leaks_list[:]

            for leak in pwnage_json:

                leaks_list.append(leak["Name"])

            print ("[MATCHED] [HAVEIBEENPWNED] {account}"
                   .format(account=account))

        if leaks_list:
            pwned_accounts[account] = leaks_list

    return pwned_accounts


def hesidohackeado(accounts, pwned_accounts, headers):

    print("--------------")
    print("HESIDOHACKEADO")
    print("--------------")

    for account in accounts:

        print (account)

        # Wait for the 'no abuse' time.
        time.sleep(1.5)
        resp = requests.get(url='https://hesidohackeado.com/api?q={account}'
                                .format(account=account), headers=headers)

        leaks_list = []

        print(resp.status_code)

        if resp.status_code != 200:

            print("[ERROR] Response status code: {resp_status_code}"
                  .format(resp_status_code=resp.status_code))

            continue

        if resp.status_code == 200 and resp.json() is not None:

            pwnage_json = resp.json()

            print(pwnage_json["status"])

            if pwnage_json["status"] != "found":

                if pwnage_json["status"] == "badsintax":

                    print("[ERROR] Bad query sintax: {query}"
                          .format(query=pwnage_json["query"]))

                continue

            del leaks_list[:]

            for leak in pwnage_json["data"]:

                data_dict = {'source_provider' : leak["source_provider"], 
                             'source_url' : leak["source_url"], 
                             'details' : leak["details"]}

                leaks_list.append(data_dict)

            print("[MATCHED] [HESIDOHACKEADO] {account}"
                  .format(account=account))

        if leaks_list:
            pwned_accounts[account] = leaks_list

    return pwned_accounts


def pwnage_searcher(sources, accounts, output_file):

    headers = {'user-agent': USER_AGENT}

	print(headers[user-agent])
    
    sources_options = {'haveibeenpwned': haveibeenpwned,
                       'hesidohackeado': hesidohackeado}
    
    pwned_accounts = {}

    if output_file is not None:
        output_file = output_file
    else:
        output_file = './pwned_accounts.txt'

    if sources != 'all':
        source = sources_options[sources]
        source(accounts, pwned_accounts, headers)
    else:
        haveibeenpwned(accounts, pwned_accounts, headers)
        hesidohackeado(accounts, pwned_accounts, headers)

    with open(output_file, 'w') as pwnage_file:
        json.dump(pwned_accounts, pwnage_file, sort_keys=True, indent=4)


def main():

    source_list = ['all', 'haveibeenpwned', 'hesidohackeado']

    # TODO: Range of arguments.
    # TODO: Excluding sources.

    parser = argparse.ArgumentParser(description="PWNAGE FINDER: User "
                                                 "enumerator and credential "
                                                 "leakage finder.")
    parser.add_argument("-s", "--sources", 
                        default='all', 
                        nargs='?', 
                        choices=source_list, 
                        help="Sources to search from (default: all).")
    parser.add_argument("-e", "--file-email-list", 
                        help="Use an already set up email list.")
    # parser.add_argument("-c", "--file-complete-names", 
    #                     help="Load a file with complete names")
    parser.add_argument("-n", "--file-user-names", 
                        help="Load the user names file.")
    parser.add_argument("-u", "--file-user-surnames", 
                        help="Load the user surnames file.")
    parser.add_argument("-d", "--file-email-domains", 
                        help="Load the email domains file.")
    parser.add_argument("-f", "--output-file", help="Specify the output file.")
    args = parser.parse_args()
    
    accounts = []

    if args.file_email_list is not None:
        file_email_list = args.file_email_list
        
        # Load emails from file.
        with open(file_email_list) as file_email_list:
            accounts = file_email_list.read().splitlines()

    # COMPLETE NAMES FUNCTIONALITY: Hard to parse multiple worded names 
    # and surnames.
    # 
    # elif args.file_complete_names is not None:
    #     file_complete_names = args.file_complete_names
    # 
    #     # Load complete names from file.
    #     with open(file_complete_names) as file_complete_names:
    #     account = file_complete_names.read().splitlines()

    else:
        # Create accounts from names, surnames and domains files.
        accounts = account_creator(args.file_user_names, 
                                   args.file_user_surnames, 
                                   args.file_email_domains)

    pwnage_searcher(args.sources, accounts, args.output_file)


if __name__ == "__main__":
    main()

