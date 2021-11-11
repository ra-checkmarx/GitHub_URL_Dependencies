from bs4 import BeautifulSoup
import requests
from greetings import hello


# Log messages
NO_RESULTS_MSG = f'No results for %s.'
NO_REFERENCES_MSG = f'No references for %s.'

# Advisories
SNYK_URL = 'https://snyk.io'
WHITE_SOURCE_URL = 'https://www.whitesourcesoftware.com/vulnerability-database/'
VERACODE_URL = 'https://sca.analysiscenter.veracode.com/vulnerability-database/search#query='
RAPID7_URL = 'https://www.rapid7.com'
RAPID7_SEARCH_VULN = 'https://www.rapid7.com/db/?q='
HACKERONE_VULN_DB = 'https://hackerone.com/hacktivity?querystring='

# GSHA Attributes
ADV_TEXT_CLASS = 'Box-title flex-auto'
ADV_HREF_CLASS = 'Link--primary v-align-middle no-underline h4 js-navigation-open'



def get_ghsa_id(cve):
    url = f'https://github.com/advisories?query={cve}'

    response = requests.get(url)
    document = BeautifulSoup(response.text, "html.parser")

    adv_text = document.find('h2', class_=ADV_TEXT_CLASS).text.strip()
    adv_number = adv_text.strip()[0]
    print(f'Available advisories: {adv_number}')

    if int(adv_number) == 0:
        print('0 Advisories available.', end='\n')
        return None
    else:
        adv_ref = document.find('a', class_=ADV_HREF_CLASS)['href']
        adv_id = adv_ref.split('/')[2]
        print(f'Advisory Id: {adv_id}')
        return adv_id






def get_ghsa_references(ghsa_id):

    if ghsa_id:
        url = f'https://github.com/advisories/{ghsa_id}'
        response = requests.get(url)
        document = BeautifulSoup(response.text, "html.parser")
        markdown_body = document.find(class_="markdown-body comment-body p-0")

        for a in markdown_body.findAll('a'):
            print(f'{a.text}: ' + a['href'])

    else:
        print(NO_RESULTS_MSG)


def get_snyk_link(cve):
    url = f'https://snyk.io/vuln/search?q={cve}&type=any'
    response = requests.get(url)
    document = BeautifulSoup(response.text, "html.parser")

    if document.find(class_='prose'):
        print(NO_RESULTS_MSG)
        return
    else:
        vul_table = document.table
        vul_link = vul_table.a['href']
        return SNYK_URL + vul_link


def get_snyk_references(cve):

    url = get_snyk_link(cve)
    if url:
        if len(url) > 1:
            print(f'There is more then one report for {cve}, please check it manually.')
        else:
            response = requests.get(url)
            document = BeautifulSoup(response.text, "html.parser")
            card_content = document.find(class_="card card--markdown")
            for a in card_content.findAll('a'):
                print(f'{a.text}: ' + a['href'])
    else:
        print(NO_RESULTS_MSG)


def get_whitesource_references(cve):

    response = requests.get(WHITE_SOURCE_URL + cve)
    document = BeautifulSoup(response.text, "html.parser")
    references = document.find(class_="references")
    for a in references.findAll('a'):
       print(f'{a.text}: ' + a['href'])


def get_veracode_references(cve):

    response = requests.get(VERACODE_URL + cve)
    document = BeautifulSoup(response.text, "html.parser")
    references = document.find(class_="references")

    if references:
        for a in references.findAll('a'):
            print(f'{a.text}: ' + a['href'])
    else:
        print(NO_RESULTS_MSG)



def get_rapit7_references(cve):

    response = requests.get(RAPID7_SEARCH_VULN + cve)
    document = BeautifulSoup(response.text, "html.parser")
    results = document.find(class_="vulndb__results")

    if results:
        adv_id = results.a['href']
        response = requests.get(RAPID7_URL + adv_id)
        document = BeautifulSoup(response.text, "html.parser")
        references = document.find(class_="vulndb__related")

        if references:
            a_tags = references.findAll('a')
            if len(a_tags) == 0:
                print(NO_REFERENCES_MSG)
            else:
                for a in a_tags:
                    print(f'{a.text}: ' + a['href'])
        else:
            print('[WARN] Please check the Rapid7 CVE results. The Vulnerability ID exists, but the references panel '
                  'is not available.')
    else:
        print(NO_RESULTS_MSG)


# Ongoing
def get_hackerone_references(cve):

    response = requests.get(HACKERONE_VULN_DB + cve)
    document = BeautifulSoup(response.text, "html.parser")
    print(document)
    references = document.find(class_="vertical-spacing")
    print(references)


def get_advisories_refences_by_cve(cve):

    print('\n\n')
    print('[GHSA]', end='\n')
    ghsa_id = get_ghsa_id(cve)
    get_ghsa_references(ghsa_id)
    print('\n')

    print('[SNYK]', end='\n')
    get_snyk_references(cve)
    print('\n')

    print('[WhiteSource]', end='\n')
    get_whitesource_references(cve)
    print('\n')

    print('[VeraCode]', end='\n')
    get_veracode_references(cve)
    print('\n')

    print('[Rapid7]', end='\n')
    get_rapit7_references(cve)
    print('\n')



def pretty_prompt():

    print('\n\n')
    print('###################################################################', end='\n')
    print('###################################################################', end='\n\n')
    print('SEARCH MODE:', end='\n')
    print('[0] - To search by the CVE ID')
    print('[1] - To search by the GHSA ID    [Under Development]', end='\n\n')
    hello('hello World!')


def main():
    pretty_prompt()

    mode = input('Mode: ')
    if int(mode) == 0:
        cve = input('CVE ID: ')
        # validate the pattern
        get_advisories_refences_by_cve(cve)
    else:
        print(f'Bad option!')
        print(f'Try Again!')


if __name__ == '__main__':
    main()
