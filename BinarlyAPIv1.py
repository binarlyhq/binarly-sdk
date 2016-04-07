#!/usr/bin/env python
"""
Module to interact with Binarly services <https://www.binar.ly>

This module provides programmatic access to APIs for:
    * Fast arbitrary length lookups in millions of indexed files
    * Automatic file-based IOC generation from files or clusters of files
    * Machine Learning assisted file labeling (clean/malicious)
    * Instant YARA <https://plusvic.github.io/yara/> rule based file search/hunting

The core of Binarly is a custom, in-house built database that is optimized
for indexing binary files (file type agnostic).
"""

import json
import time
import hashlib
import requests

API_V1_ROOT = "{}/api/v1"
SEARCH_ROOT = "{}/search".format(API_V1_ROOT)
MULTISEARCH_ROOT = "{}/multisearch".format(API_V1_ROOT)
HUNT_ROOT = "{}/hunt".format(API_V1_ROOT)
LABEL_ROOT = "{}/label".format(API_V1_ROOT)
SIGN_ROOT = "{}/sign".format(API_V1_ROOT)
STATS_ROOT = "{}/stats".format(API_V1_ROOT)
METADATA_ROOT = "{}/metadata".format(API_V1_ROOT)
REQUESTS_ROOT = "{}/requests".format(API_V1_ROOT)
UPLOAD_ROOT = "{}/upload".format(API_V1_ROOT)
CHECKSAMPLE_ROOT = "{}/checksample".format(API_V1_ROOT)

MAX_CHUNK = 50

class InvalidAPIKey(Exception):
    """Exception class to indicate an API key was found during the request"""
    def __init__(self, value):
        Exception.__init__(self)
        self.value = value

    def __str__(self):
        return repr(self.value)

class BadRequest(Exception):
    """Exception class to indicate an invalid request was encountered."""
    def __init__(self, value):
        Exception.__init__(self)
        self.value = value

    def __str__(self):
        return repr(self.value)

def get_file_sha1(path):
    """Helper function to compute SHA1 of given ``path``"""
    hashval = hashlib.sha1()
    with open(path, 'rb') as inputfile:
        while True:
            chunk = inputfile.read(80 * 1024 * 1024)
            if len(chunk) == 0:
                break
            hashval.update(chunk)
    return str(hashval.hexdigest()).lower()

def hex_pattern(pattern):
    """
    Build an "object" that indicates that the ``pattern``
    is a hex sequence
    """
    return {'type':'hex', 'value':pattern}

def ascii_pattern(value):
    """
    Build an "object" that indicates that the ``pattern``
    is an ASCII string
    """
    return {'type':'ascii', 'value':value}

def wide_pattern(value):
    """
    Build an "object" that indicates that the ``pattern``
    is a Unicode string
    """
    return {'type':'wide', 'value':value}

def build_query(patterns):
    """
    Build a search "object" for multisearch
    """
    if isinstance(patterns, list):
        return {"patterns":patterns}
    else:
        return {"patterns":[patterns]}

class BinarlyAPI(object):
    """BinarlyAPI v.1.0 work class"""
    def __init__(self, api_key, proxy=None, server="www.binar.ly", use_http=False, project="SDK"):
        """Construct an API object to communicate with the services.

        Parameters:
            * ``api_key`` - unique key that enables you to access the services
            * ``proxy``   - proxy to use for communication. If ``use_ssl`` is enabled \
            the proxy has to be secure as well
            * ``server``  - specify the endpoint for the API
            * ``use_http`` - specify if the communication should be using HTTPS.\
            By default this is set to true but can be disabled to achieve maximum performance. \
            This applies to to automation scripts and tools. (Default=False)

            * ``project`` - name of the project that uses the API. \
            This is sent in the user-agent header.
        """
        if len(api_key) != 36:
            raise RuntimeError("Invalid Binarly APIKey. Please register and get your key at https://wwww.binar.ly")

        self.key = api_key
        if use_http:
            self.server = "http://{}".format(server)
        else:
            self.server = "https://{}".format(server)

        self.proxy = proxy
        self.sdk = 'BinarlyAPI Python {}/1.0'.format(project)
        self.session = requests.Session()
        self.session.headers.update({'Binarly-ApiKey':self.key, 'User-Agent':self.sdk})
        if proxy:
            if use_http:
                self.session.proxies.update({"http": proxy})
            else:
                self.session.proxies.update({"https": proxy})

    def __post(self, url, data):
        """
        POST helper function

        Returns JSON reply
        """
        response = self.session.post(url, data=data)
        if response.status_code == 403:
            raise InvalidAPIKey("Invalid API Key")
        elif response.status_code == 400:
            raise BadRequest("Bad Request")

        return response.json()

    def __get(self, url, data=None):
        """GET helper function"""
        response = self.session.get(url, data=data)
        if response.status_code == 403:
            raise InvalidAPIKey("Invalid API Key")
        elif response.status_code == 400:
            raise BadRequest("Bad Request")

        if response.headers['Content-Type'] == 'application/json':
            return response.json()
        else:
            return response.text

    def build_url(self, url_path, **kwargs):
        """Helper function to construct URL from given args"""
        uri = url_path.format(self.server)
        if len(kwargs) == 0:
            return uri
        uri += "?"
        for parameter, value in kwargs.items():
            uri += parameter
            uri += "="
            uri += str(value)
            uri += "&"
        return uri

    @staticmethod
    def __get_multisearch_obj(patterns, limit):
        """Construct a multisearch search object from provided arguments:

            * ``pattterns`` - vector of patterns to search for.
            * ``limit``     - limit the number of returned results.
        """
        search_obj = {}
        search_obj['limit'] = limit
        search_obj['requests'] = patterns
        return json.dumps(search_obj)

    @staticmethod
    def __get_search_obj(patterns, limit, exact):
        """Construct a search object from provided arguments.

        Parameters:
            * ``pattterns`` - vector of patterns to search form
            * ``limit``     - limit the number of returned results
            * ``exact``     - specifiy if the search should be exact
        """
        search_obj = {}
        search_obj['limit'] = limit
        if exact:
            search_obj['exact'] = 'yes'

        if isinstance(patterns, list):
            search_obj['patterns'] = patterns
        else:
            search_obj['patterns'] = [patterns]

        return json.dumps(search_obj)

    def __await_req_iter(self, response, status_callback=None, wait_time=0.2):
        """Helper function which iterates over the sync or async request
        done by the API.
        """
        if not response.has_key('resource'):
            # process waiting for sync req
            yield response
            next_page = response['next_page']
            while next_page:
                response = self.__get(next_page)
                next_page = response['next_page']
                yield response
            return
        else:
            # process waiting for async req
            next_page = response['resource']
            response = self.__get(next_page)
            previous_response = None
            while True:
                if response['status'] != previous_response and status_callback != None:
                    status_callback(response)

                previous_response = response['status']
                if response['status'] in ['done', 'failed']:
                    break

                if response.get('next_page', None) != None:
                    yield response

                    if response['next_page']:
                        next_page = response['next_page']
                        response = self.__get(next_page)
                        continue
                else:
                    # re-retrieve current page
                    time.sleep(wait_time)
                    response = self.__get(next_page)
            yield response

    def search_iter(self, patterns, limit=20, exact=False):
        """Search iterator for walking the results page by page

        Parameters:
            * ``patterns`` - a list of patterns that should contained in all of the results
            * ``limit``    - number of results to retrieve at most (*default=20*)
            * ``exact``    - validate results in order to eliminate FPs (default=False)

        Yeilds a dictionary containg stats about the number of files found and the list of results.

        Example response::

        >>{
        >>  "stats": {
        >>    "time_ms": 4.41,
        >>    "total_count": 7251268,
        >>    "clean_count": 3797000,
        >>    "malware_count": 2796428,
        >>    "suspicious_count": 94902,
        >>    "pua_count": 562932,
        >>    "unknown_count": 6
        >>  },
        >>  "status": "done",
        >>  "results": [
        >>    {
        >>      "sha1": "03b113ca12f4b2bc5ca9136aeb28adc058860b90",
        >>      "label": "clean"
        >>    },
        >>    {
        >>      "sha1": "03b11416f75ab0b16b44afae84cb850d4d8540e9",
        >>      "label": "clean"
        >>    },
        >>    ...
        >>    {}
        >>
        >>  ],
        >>  "next_page": null,
        >>}
        """
        search_data = self.__get_search_obj(patterns, limit, exact)
        url = self.build_url(SEARCH_ROOT)

        for page in self.__await_req_iter(self.__get(url, search_data)):
            yield page


    def multisearch_iter(self, patterns, limit=20):
        """MultiSearch iterator for walking the results page by page.
        The search is done in batch of size `MAX_CHUNK`. This means that if a query contains
        more than `MAX_CHUNK` patterns to be searched for, it will be split in sub-queries.

        Parameters:
            * ``patterns`` - a list of patterns that should contained in all of the results
            * ``limit``    - number of results to retrieve at most (default=20)

        Yields:

        Tuple (`result_index`, `response`) where
            * `result_index` - index in the patterns list of the first pattern that was searched.\
            This will be a multiple of `MAX_CHUNK`.
            * `response` - reply with results for the currenty batch of the search

        Example `response`::

        >>{
        >>  "requests": [
        >>    {
        >>      "status": "done",
        >>      "stats": {
        >>        "total_count": 4055268,
        >>        "clean_count": 2425110,
        >>        "malware_count": 1359561,
        >>        "suspicious_count": 47015,
        >>        "pua_count": 223581,
        >>        "unknown_count": 1
        >>      },
        >>      "results": [
        >>        {
        >>          "sha1": "03b113ca12f4b2bc5ca9136aeb28adc058860b90",
        >>          "label": "clean"
        >>        },
        >>        {
        >>          "sha1": "03b11416f75ab0b16b44afae84cb850d4d8540e9",
        >>          "label": "clean"
        >>        }
        >>      ]
        >>    },
        >>    {
        >>      "status": "done",
        >>      "stats": {
        >>        "total_count": 24641,
        >>        "clean_count": 18794,
        >>        "malware_count": 5498,
        >>        "suspicious_count": 102,
        >>        "pua_count": 247,
        >>        "unknown_count": 0
        >>      },
        >>      "results": [
        >>        {
        >>          "sha1": "03b1f39570b46ed4c4cc48dfc3e46f26aac980c5",
        >>          "label": "clean"
        >>        },
        >>        {
        >>          "sha1": "03b30ebe26dd21e893d2d666a73d44eb99f312e8",
        >>          "label": "clean"
        >>        }
        >>      ]
        >>    }
        >>  ],
        >>  "next_page": null
        >>}
        """
        for idx in range(0, len(patterns), MAX_CHUNK):
            cur_patterns = patterns[idx:idx+MAX_CHUNK]
            search_data = self.__get_multisearch_obj(cur_patterns, limit)
            search_url = self.build_url(MULTISEARCH_ROOT)
            for json_data in self.__await_req_iter(self.__get(search_url, search_data)):
                yield (idx, json_data)

    def multisearch(self, patterns, limit=20):
        """
        Perform a multisearch for the provided ``patterns``.

        A multisearch operation returns all of the files which contain any of the
        provided paterns (OR operation).

        Parameters:
            * ``patterns`` - a list of lists of patterns to search for
            * ``limit``    - maximimum number of results to return

        Returns a dict representing all queries.

        Example::

        >>{
        >>  "requests": [
        >>    {
        >>      "status": "done",
        >>      "stats": {
        >>        "total_count": 4055268,
        >>        "clean_count": 2425110,
        >>        "malware_count": 1359561,
        >>        "suspicious_count": 47015,
        >>        "pua_count": 223581,
        >>        "unknown_count": 1
        >>      },
        >>      "results": [
        >>        {
        >>          "sha1": "03b113ca12f4b2bc5ca9136aeb28adc058860b90",
        >>          "label": "clean"
        >>        },
        >>        {
        >>          "sha1": "03b11416f75ab0b16b44afae84cb850d4d8540e9",
        >>          "label": "clean"
        >>        }
        >>      ]
        >>    },
        >>    {
        >>      "status": "done",
        >>      "stats": {
        >>        "total_count": 24641,
        >>        "clean_count": 18794,
        >>        "malware_count": 5498,
        >>        "suspicious_count": 102,
        >>        "pua_count": 247,
        >>        "unknown_count": 0
        >>      },
        >>      "results": [
        >>        {
        >>          "sha1": "03b1f39570b46ed4c4cc48dfc3e46f26aac980c5",
        >>          "label": "clean"
        >>        },
        >>        {
        >>          "sha1": "03b30ebe26dd21e893d2d666a73d44eb99f312e8",
        >>          "label": "clean"
        >>        }
        >>      ]
        >>    }
        >>  ],
        >>  "next_page": null
        >>}
        """
        result = {}
        result['requests'] = []
        query_count = len(patterns)
        for idx in xrange(0, query_count):
            result['requests'].append({'results':[], 'stats':{}, 'status':None})
        for result_index, page in self.multisearch_iter(patterns, limit):
            if page.has_key('error'):
                return page

            for idx in xrange(0, query_count):
                result['requests'][result_index+idx]['status'] = page['requests'][idx]['status']
                result['requests'][result_index+idx]['stats'] = page['requests'][idx]['stats']
                result['requests'][result_index+idx]['results'] += page['requests'][idx]['results']

        return result

    def search(self, patterns, limit=20, exact=False):
        """
        Perform a search operation for the provided ``patterns``.

        If ``patterns`` is a list it can be interpreted as returning
        the files which contain all of the patterns (AND operation)

        Returns a dict with results.

        Calling example::

        >> # retrieve first 1000 files containing bytes 00 00 00 00 and ascii string "Microsoft Corporation"
        >> result = binobj.search([hex_pattern("F00100FF"), ascii_pattern("Microsoft Corporation")], 1000)

        Example result::

        >> {
        >>   "status": "done",
        >>   "next_page": null,
        >>   "stats": {
        >>     "total_count": 1967902,
        >>     "time_ms": 4.058,
        >>     "malware_count": 623570,
        >>     "suspicious_count": 21442,
        >>     "clean_count": 1025532,
        >>     "pua_count": 297358,
        >>     "unknown_count": 0
        >>   },
        >>   "results": [
        >>     {
        >>       "size": 884688,
        >>       "sha1": "03b121a08315da13e14b279d591652f71438dd78",
        >>       "label": "clean"
        >>     },
        >>     ...
        >>     {
        >>       "size": 226480,
        >>       "sha1": "03b26f3e839751583359b2c421bfd8aa327ffec1",
        >>       "label": "clean"
        >>     }
        >>   ]
        >> }
        """
        results = {}
        results['results'] = []
        results['stats'] = {}
        for json_data in self.search_iter(patterns, limit, exact):
            if json_data.has_key("error"):
                return json_data

            results['stats'] = json_data['stats']
            results['results'] += json_data['results']

        return results

    def gen_ioc_files(self, filepaths, options=None, upload_missing=True, status_callback=None):
        """Generate one or multiple IOC Signatures that cover all or a subset
        of the provided ``filepaths``.

        If ``upload_missing`` is set to true files which are not available
        in the index will be automatically uploaded in order to compute
        classification.
        """
        filehashes = {}
        for filepath in filepaths:
            filehashes[filepath] = get_file_sha1(filepath)

        if upload_missing:
            for fpath, fhash in filehashes.iteritems():
                if not self.check_sample(fhash)['exists']:
                    self.upload_file(fpath)

        return self.gen_ioc_hashes(filehashes.values(), options, status_callback)

    def gen_ioc_hashes(self, filehashes, options=None, status_callback=None):
        """ Generate one or multiple IOC that matched the provided ``filehashes``.

        In order to succeed it is assumed that the files are already uploaded otherwise the request\
        will fail.

        Example result::

        >> {
        >>   "status": "done",
        >>   "signatures": [
        >>     {
        >>       "info": "https://www.binar.ly/api/v1/signature?sigid=767791ef-0c76-4e22-93a0-05ff154c7536&query=info",
        >>       "yarasig": "https://www.binar.ly/api/v1/signature?sigid=767791ef-0c76-4e22-93a0-05ff154c7536&query=yarasig"
        >>     }
        >>   ],
        >>   "resource": "https://www.binar.ly/api/v1/sign?reqid=6bd95d28-84d1-4a51-bdfc-00f7dbe2d626",
        >>   "creation_time": "2016-Apr-04 08:45:47",
        >>   "results": {
        >>     "b5ed7fedd7b9c339bb7a68f681c2d09876b2b64a": {
        >>       "status": "signed"
        >>     }
        >>   },
        >>   "reqid": "6bd95d28-84d1-4a51-bdfc-00f7dbe2d626",
        >>   "stats": {
        >>     "time_ms": 1000
        >>   }
        >> }
        """
        data = json.dumps({'filehashes': filehashes, 'options': options})
        return self.__await_req_iter(self.__get(self.build_url(SIGN_ROOT), data),
                                     status_callback=status_callback,
                                     wait_time=2.0).next()

    def classify_hashes(self, filehashes, status_callback=None):
        """ Takes a list ``filehashes`` of file hashes (any of md5/sha1/sha256)
        and returns a MachineLearning based classification of the files.

        Example response::

        >> {
        >>   "status": "done",
        >>   "stats": {
        >>     "time_ms": 2000
        >>   },
        >>   "creation_time": "2016-Apr-04 08:39:12",
        >>   "results": {
        >>     "45825a224affb609e1237bc06927c59a4cdadc1d": {
        >>       "family": "generic_label_99%",
        >>       "label": "malware"
        >>     },
        >>     "85d35ededc90700238c50b28b583eec364d7fddb": {
        >>       "label": "clean"
        >>     }
        >>   }
        >> }
        """
        label_data = json.dumps({'filehashes': filehashes})
        url = self.build_url(LABEL_ROOT)
        return self.__await_req_iter(self.__get(url, label_data), status_callback).next()

    def get_metadata(self, filehash):
        """Returns metadata information for file indentified with ``filehash``.

        The hash can be any of : md5,sha1 or sha256.

        Metadata can contain fileds such as:
           * filesize
           * label
           * family
           * sha1
           * sha256
           * md5
           * ssdeep
           * certificate information
           * AV detection count

        Example response::

        >>{
        >>  u'85d35ededc90700238c50b28b583eec364d7fddb': {
        >>    u'sha1': u'85d35ededc90700238c50b28b583eec364d7fddb',
        >>    u'version_info': {
        >>        u'original_file_name': u'aes.wcx',
        >>        u'file_version': u'0.6.3.397',
        >>        u'file_description': u'aes encryptor plugin for total commander'
        >>    },
        >>    u'imphash': u'3f664c0f36ccf8af8a342bc6c6cdd371',
        >>    u'detection_count': 1,
        >>    u'label': u'susp',
        >>    u'ssdeep': u'6144:xi4d6xbjyvdroy1/pqj+67a2po3+z5k/r/ikgyfn/cs12dnygjta:4bpjy9oyvqjdazv84/n+n3va',
        >>    u'sha256': u'bb44e22d9ff004c7164f92dde5fb341212754e87adf022193c0d6feeb3fa96de',
        >>    u'md5': u'1d4d7813ac0655338ee269b9d38ba548',
        >>     u'size': 335364}
        >>}
        """
        url = self.build_url(METADATA_ROOT, filehash=filehash)
        return self.__get(url)

    def classify_files(self, filepaths, upload_missing=True, status_callback=None):
        """Return MachineLearning based classification of given ``filepaths``
        If ``upload_missing`` is set to True, files which are not present
        in the collection will be automatically uploaded.
        """
        filehashes = {}
        for filepath in filepaths:
            filehashes[filepath] = get_file_sha1(filepath)

        if upload_missing:
            for fpath, fhash in filehashes.iteritems():
                if not self.check_sample(fhash)['exists']:
                    self.upload_file(fpath)

        return self.classify_hashes(filehashes.values(), status_callback)

    def get_request(self, requrl):
        """Helper function to return API result from ``requrl``
        using current credentials
        """
        return self.__get(requrl)

    def get_request_type_iter(self, reqtype):
        """Iterate over requests of type ``reqtype`` which were requested
        from the current account.

        ``reqtype`` can be:

           * "sign" - returns all sign requests
           * "hunt" - returns all YARA hunting requests
           * "exact_search" - returns all exact search requests
        """
        url = self.build_url(REQUESTS_ROOT, type=reqtype)
        for page in self.__await_req_iter(self.__get(url)):
            yield page

    def check_sample(self, filehash):
        """Checks if a file uniquely identified by ``filehash`` (md5/sha1/sha256) is
        already known to binarly and can be automatically analyzed without
        uploading it.
        """
        url = self.build_url(CHECKSAMPLE_ROOT, filehash=filehash)
        return self.__get(url)

    def stats(self):
        """Returns statistics about the files indexed in binar.ly"""
        url = self.build_url(STATS_ROOT)
        return self.__get(url)

    def upload_file(self, filepath):
        """Uploads file.
        This is need in case the file is not already in collection - this\
        can be checked using `check_sample` API.

        This is used before generating IOCs or classifying files.
        """
        filehash = get_file_sha1(filepath)
        with open(filepath, 'rb') as filehandle:
            self.session.post(self.build_url(UPLOAD_ROOT), files={filehash : filehandle})
            return True

        return True

    def yara_hunt(self, rule_path, status_callback=None):
        """Performs a YARA Scan using the yara rule specified by ``rule_path``
        over all of the files in the collection.

        Unlike normal searches, YARA based hunting validates results before returning\
        them. No FPs are returned.

        Example result::

        >>{
        >>  "creation_time": "2016-Mar-28 09:07:01",
        >>  "status": "done",
        >>  "stats": {
        >>    "time_ms": 6000,
        >>    "total_count": 24,
        >>    "clean_count": 0,
        >>    "malware_count": 24,
        >>    "suspicious_count": 0,
        >>    "pua_count": 0,
        >>    "unknown_count": 0
        >>  },
        >>  "results": [
        >>    {
        >>      "sha1": "11330f683c67e333062fee8c4e0c8b3b29b48a67",
        >>      "label": "malware",
        >>      "family": "reveton",
        >>      "file_size": 129024
        >>    },
        >>    {
        >>      "sha1": "2e9250cec683464437d8b1cece072023ee07c22b",
        >>      "label": "malware",
        >>      "family": "reveton",
        >>      "file_size": "278016"
        >>    },
        >>    {
        >>      "sha1": "43345f0b5b9bf66be3a5da6f0ebf407f0e7afdc6",
        >>      "label": "malware",
        >>      "family": "reveton",
        >>      "file_size": 153088
        >>    },
        >>    ...
        >>    {
        >>      "sha1": "d0513c86680c7f6af3d5b1000524b07df2750dd2",
        >>      "label": "malware",
        >>      "family": "reveton",
        >>      "file_size": 151552
        >>    }
        >>  ]
        >>}
        """
        fcontents = ''
        with open(rule_path, 'rb') as yarafile:
            fcontents = yarafile.read()
            try:
                # Python 3.x
                fcontents = bytes(fcontents, 'utf-8')
            except TypeError:
                # Python 2.x
                fcontents = str(fcontents)

        return self.__await_req_iter(
            self.__get(self.build_url(HUNT_ROOT), fcontents),
            status_callback=status_callback).next()
