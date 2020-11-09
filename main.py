# POC for Most-Seen-CA-Trust-Seeding

import logging
import certstream
import json
from io import StringIO
import datetime
import sys
import time
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style
from collections import OrderedDict
import pem
from OpenSSL import crypto
import hashlib

style.use('fivethirtyeight')

# setup logging
logger = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


class RootCATrustStore:
    def __init__(self, from_bundle=None):
        self.trust_bundle = OrderedDict()

        if from_bundle:
            self.load_pem_trust_bundle(from_bundle)

    def load_pem_trust_bundle(self, pem_file_path):
        trust_bundle_parsed = pem.parse_file(pem_file_path)

        for cert in trust_bundle_parsed:
            cert_pem = crypto.load_certificate(crypto.FILETYPE_PEM, str(cert))
            # convert pem to der format
            cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_pem)
            # calculate sha1 over der format
            sha1_cert_der = hashlib.sha1()
            sha1_cert_der.update(cert_der)
            hexdigest = sha1_cert_der.hexdigest()
            hexdigest2 = ':'.join(
                hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2)).upper()
            logger.debug(f"add {hexdigest2} to RootCaTrustStore")
            self.trust_bundle[hexdigest2] = str(cert)


class RootCertificate:
    def __init__(self, fingerprint, seen_count, first_seen_time, ct_data, pem_data):
        self.fingerprint = fingerprint
        self.seen_count = seen_count
        self.ct_data = ct_data

        self.pem_data = pem_data

        self.plot_time_seen_count_data = [(first_seen_time, 1)]

    def seen(self, time):
        self.seen_count += 1
        self.plot_time_seen_count_data.append((time, self.seen_count))

    def __str__(self):
        return self.fingerprint


class TrustSeeding:
    def __init__(self, url, ref_trust_store, new_bundle_path):
        self.url = url
        self.ref_trust_store = ref_trust_store

        # stats
        self.message_type_stats = {}
        self.message_count_stats = 0
        self.remember_root_certs = {}

        # for plotting
        self.start_time_seconds = 0
        # (x, y) tuple
        self.seencount_data = []

        # write result to this file
        self.new_bundle_path = new_bundle_path

    def callback(self, message, context):
        """
        :param message: message as json
        """
        if "message_type" in message:
            if message["message_type"] in self.message_type_stats:
                self.message_type_stats[message["message_type"]] += 1
            else:
                self.message_type_stats[message["message_type"]] = 1

        if "data" in message:
            if "chain" in message["data"]:
                root_ca_fingerprint = message["data"]["chain"][-1]["fingerprint"]
                if root_ca_fingerprint in self.remember_root_certs:
                    self.remember_root_certs[root_ca_fingerprint].seen((time.time() - self.start_time_seconds))
                else:
                    # write missing message in case of an error to the final
                    # result, but as a comment.
                    pem_data = f"# PEM DATA MISSING FOR {root_ca_fingerprint}"
                    if root_ca_fingerprint in self.ref_trust_store.trust_bundle:
                        pem_data = self.ref_trust_store.trust_bundle[root_ca_fingerprint]

                    root_ca_cert = RootCertificate(
                        fingerprint=root_ca_fingerprint,
                        seen_count=1,
                        first_seen_time=(time.time() - self.start_time_seconds),
                        ct_data=message["data"]["chain"][-1],
                        pem_data=pem_data
                    )
                    self.remember_root_certs[root_ca_fingerprint] = root_ca_cert

        self.message_count_stats += 1

    def on_open(self):
        logger.info(f"Connection was successfull, Stop with KeyboardInterrupt")

    def on_error(self, exception):
        logger.error(f"Exception in CertStreamClient! -> {exception}")

    def start(self):
        start_datetime = datetime.datetime.now()
        self.start_time_seconds = time.time()
        # this reacts to keyboard interrupt
        certstream.listen_for_events(self.callback, on_open=self.on_open,
                                     on_error=self.on_error, url=self.url)
        end_datetime = datetime.datetime.now()
        duration_datetime = end_datetime - start_datetime
        logger.info(f"Duration: {duration_datetime}.")
        logger.info(f"Message Type Stats: {len(self.message_type_stats)}.")
        logger.info(f"Message Count Stats: {self.message_count_stats}.")

        logger.info(f"Observed Root Certs: {len(self.remember_root_certs.keys())}")

        fingerprint_seencount = [(key, value.seen_count) for key, value in self.remember_root_certs.items()]

        sorted_fingerprint_seencount = sorted(fingerprint_seencount, key=lambda tup: tup[1], reverse=True)

        with open(self.new_bundle_path, "w") as f:
            for fp, seen_count in sorted_fingerprint_seencount:
                logger.info(f"{fp} : {seen_count}")
                f.write(self.remember_root_certs[fp].pem_data + "\n\n")

        logger.info(f"result written to {self.new_bundle_path}.")

        # plot top 10 certificates
        fig = plt.figure()

        for i in range(10):
            tmp_axis = fig.add_subplot(1, 1, 1)

            plot_time_seen_count_data = self.remember_root_certs[
                sorted_fingerprint_seencount[i][0]].plot_time_seen_count_data

            xs = [z[0] for z in plot_time_seen_count_data]
            ys = [z[1] for z in plot_time_seen_count_data]

            tmp_axis.plot(xs, ys)

        plt.show()


def main():
    logger.info("TrustSeeding Startup")
    logger.info("Init Mozilla Trust Store with Fingerprints")
    mozilla_trust_store = RootCATrustStore(from_bundle="mozilla-2020-10-14.pem")
    logger.info(f"{len(mozilla_trust_store.trust_bundle)} certs added")
    logger.info(f"Mozilla Trust Store Initialized")
    manager = TrustSeeding(
        url="wss://certstream.calidog.io/",
        # it's also acts as a whitelist
        ref_trust_store=mozilla_trust_store,
        new_bundle_path="user_bundle.pem"
    )
    manager.start()


if __name__ == "__main__":
    main()
