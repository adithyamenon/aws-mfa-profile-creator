#!/usr/bin/env python

import argparse
import configparser
import logging
import signal
import subprocess
import sys
import re
import boto3
import os
from colorama import Fore, Back, Style

from os.path import expanduser, join

MFA_DEVICE_ID = 'mfa_device_id'
TOKEN_DURATION = 'token_duration'

logging.basicConfig(level=logging.INFO)
logging.getLogger()
logger = logging.getLogger()

def signal_handler(signal, frame):
    """
    Catch interrupts and exit without a stack trace.
    """
    print('\n\nExiting...\n')
    sys.exit(0)

def show_version():
    """
    Show version info and exit.
    """
    print('{name} version {ver}\n'.format(name=PROGNAME, ver=VERSION))
    sys.exit(0)

def read_aws_file(filepath):
    """
    Read AWS config file.
    """
    if not (os.path.isfile(filepath)):
        print(Fore.RED+ "AWS credentials/config file is missing. Please configure using `aws config` command." + Style.RESET_ALL)
        exit(1)
    else:
        # print("\nCredentials file found. Proceeding...")
        config = configparser.ConfigParser()
        config.read(filepath)

    return config

def profile_selection(aws_creds):
    """
    User selection of aws profile.
    """
    choices= list()
    profile_count= 0

    for key, key_val in aws_creds.items():
        if "mfa" not in key and key != 'DEFAULT':
            profile_count += 1
            choices.append(key)
            print('{count}: {k}'.format(count=profile_count, k=key))

    while True:
        user_input = input('\nPick your AWS profile from the list above: ')
        try:
            selection = int(user_input) - 1
            if int(selection) in range(0, profile_count + 1):
                break
        except ValueError:
            pass

        print(Fore.RED+"Invalid Selection. Please select again."+ Style.RESET_ALL)

    selected_profile= choices[int(selection)]
    return selected_profile

def get_mfa_device(config, selected_profile):
    """
    Verify if config has custom key [mfa_device_id] to identify mfa device. 
    If not, ask user for inputs: 
        - AWS Account Number
        - AWS Username
    to create mfa serial id and add on config file for future use.
    """
    if selected_profile == 'default':
        full_profile = 'default'
    else:
        full_profile = 'profile {n}'.format(n=selected_profile)
    
    global aws_config_file

    try:
        mfa_device_id = config[full_profile][MFA_DEVICE_ID]
    except KeyError:
        print(Fore.RED+'\nERROR: You must add {c} to your AWS conf profile with the ARN of your MFA device! Example: \
\n'+Fore.YELLOW+'[profile {p}]\n\
{c} = arn:aws:iam::ACCOUNT-NUMBER-WITHOUT-HYPHENS:mfa/MFA-DEVICE-ID\n'.format(
            c=MFA_DEVICE_ID, p=selected_profile)+ Style.RESET_ALL)

        user_add_device= str()

        while user_add_device not in ['yes','no']:
            user_add_device= input('\nDo you want to create mfa device entry on selected profile? (yes/no): ')
            
            if user_add_device == 'yes':
                while True:
                    account_number= input('AWS Account Number: ')
                    pattern= r'^[0-9]*$'
                    if re.match(pattern,account_number) and len(account_number) > 0:
                        break
                    else:
                        print(Fore.RED+ "Invalid Account Number. Enter Again!" + Style.RESET_ALL)

                aws_username= input('AWS Username: ')
                device_id= "arn:aws:iam::"+ str(account_number)+ ":mfa/" + str(aws_username)

                print("Adding device id `"+str(device_id)+"` in aws config file...")

                if selected_profile == 'default':
                    config[selected_profile][MFA_DEVICE_ID]= device_id
                else:
                    config[full_profile][MFA_DEVICE_ID]= device_id    

                save_aws_file(aws_config_file, config)
                return device_id

            elif user_add_device == 'no':
                print("OK. Exiting...")
                exit(1)

            else:
                print(Fore.RED+ "Invalid Entry. Try Again."+ Style.RESET_ALL)
    
    return mfa_device_id

    # return mfa_device_id
def duration_override(config, selected_profile):
    """
    Verify if config has custom key [token_duration] to override default duration.
    If not, use the default duration - 8hrs.
    """
    if selected_profile == 'default':
        full_profile = 'default'
    else:
        full_profile = 'profile {n}'.format(n=selected_profile)
    
    global aws_config_file

    try:
        token_duration = config[full_profile][TOKEN_DURATION]
    except KeyError:
        token_duration = 28800
    
    return token_duration

def mfa_entry():
    """
    User input of MFA token and validation
    """

    while True:
        mfa_code= input('Enter code from MFA device: ')
        pattern= r'^[0-9]*$'
        if re.match(pattern,mfa_code) and len(mfa_code) == 6:
            break
        else:
            print(Fore.RED +"Invalid MFA Code. Please enter again" + Style.RESET_ALL)

    return mfa_code

def get_sts_creds(selected_profile, duration, device_id, mfa_code):
    """
    Get STS creds from AWS using selected_profile, device_id and mfa_code
    """

    sts_session = boto3.Session(profile_name=selected_profile)
    sts_client= sts_session.client('sts')

    sts_creds = sts_client.get_session_token(
        DurationSeconds=duration,
        SerialNumber="{device_id}".format(device_id=device_id),
        TokenCode=mfa_code
    )

    return sts_creds

def update_aws_creds(aws_creds, profile, sts_creds):
    """
    Create new profile with prefix as '-mfa' with STS credentials.
    Add new profile to AWS credentials file.
    """
    global aws_creds_file

    sts_profile = '{p}{s}'.format(p=profile, s='-mfa')
    if sts_profile not in aws_creds:
        aws_creds[sts_profile] = dict()

    credentials = sts_creds['Credentials']
    aws_creds[sts_profile]['aws_access_key_id'] = credentials['AccessKeyId']
    aws_creds[sts_profile]['aws_secret_access_key'] = credentials['SecretAccessKey']
    aws_creds[sts_profile]['aws_security_token'] = credentials['SessionToken']

    save_aws_file(aws_creds_file, aws_creds)

    return sts_profile


def save_aws_file(aws_file, config):
    """
    Write into AWS credential or config file.
    """
    with open(aws_file, 'w') as configfile:
        config.write(configfile)
    return
    
def main():
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(description='AWS MFA Profile Creator\n\n' +
                                                 'Automates obtaining and updating AWS credentails with' +
                                                 ' STS tokens',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug logging')
    parser.add_argument('-v', '--version', action='store_true', help='show version and exit')
    args = parser.parse_args()

    # handle flags
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.version:
        show_version()

    user_home = expanduser("~")

    global aws_config_file, aws_creds_file

    aws_creds_file = join(user_home, '.aws', 'credentials')
    aws_config_file = join(user_home, '.aws', 'config')

    aws_creds = read_aws_file(aws_creds_file)
    aws_conf = read_aws_file(aws_config_file)

    selected_profile = profile_selection(aws_creds)

    device_id = get_mfa_device(aws_conf, selected_profile)

    duration = duration_override(aws_conf, selected_profile)

    mfa_code = mfa_entry()

    sts_creds= get_sts_creds(selected_profile, duration, device_id, mfa_code)

    sts_profile = update_aws_creds(aws_creds, selected_profile, sts_creds)

    export_cmd= "export AWS_DEFAULT_PROFILE=" + str(sts_profile)
    os.system(export_cmd)

    print(Fore.YELLOW +'\nUpdated AWS profile {p} with STS credentials and exported as default profile!'.format(p=sts_profile)+ Style.RESET_ALL)
    print('To reset profile, execute the command:\n\t\t'+Fore.MAGENTA+'`export AWS_DEFAULT_PROFILE=<profile-name>`'+ Style.RESET_ALL )      


# if __name__ == '__main__':
#     main()