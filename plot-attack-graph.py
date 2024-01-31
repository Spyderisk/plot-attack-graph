#!/usr/bin/python3

# Copyright 2023 University of Southampton IT Innovation Centre

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import csv
import gzip
import logging
import re
import sys
import tempfile
import textwrap
import time
from collections import defaultdict
from itertools import chain
from pathlib import Path

import boolean
from graphviz import Digraph
from rdflib import ConjunctiveGraph, Literal, URIRef

VERSION = "1.0"

algebra = boolean.BooleanAlgebra()
TRUE, FALSE, NOT, AND, OR, symbol = algebra.definition()

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

parser = argparse.ArgumentParser(description="Plot attack graphs for Spyderisk system models",
                                 epilog="e.g. plot-attack-graph.py -i SteelMill.nq.gz -o steel.pdf -d ../domain-network/csv/ -m MS-LossOfControl-f8b49f60 MS-LossOfReliability-f8b49f60 --and --or --hide-misbehaviours --hide-secondary-threats --external-causes --initial-causes --hide-link-labels --hide-likelihood-in-description --hide-node-titles --compact --text-width 30")
parser.add_argument("-i", "--input", dest="input", required=True, metavar="input_NQ_filename", help="Filename of the validated system model NQ file (compressed or not)")
parser.add_argument("-o", "--output", dest="output", required=True, metavar="output_image_filename", help="Output filename (PDF, SVG or PNG)")
parser.add_argument("-d", "--domain", dest="csvs", required=True, metavar="CSV_directory", help="Directory containing the domain model CSV files")
parser.add_argument("-m", "--misbehaviour", dest="misbehaviours", required=True, nargs="+", metavar="URI_fragment", help="Target misbehaviour IDs, e.g. 'MS-LossOfControl-f8b49f60'")

parser.add_argument("--plot-direction", dest="plot_direction", choices=['BT', 'TB', 'RL', 'LR'], default='TB', help="The direction of the plot from causes to effects (B=bottom, T=top, L=left, R=right)")
parser.add_argument("--current-risk", action='store_true', help="Run in current (not future) risk mode, affecting the control strategies proposed")
parser.add_argument("--limit-logic", action='store_true', help="Compute the logical expressions to only target nodes on the shortest paths")
parser.add_argument("--and", action="store_true", help="Add explicit AND nodes to the displayed graph")
parser.add_argument("--or", action="store_true", help="Add explicit OR nodes to the displayed graph")
parser.add_argument("--all-routes", action='store_true', help="Show all routes through the graph, not just the shortest")
parser.add_argument("--highlight-short-routes", action='store_true', help="Highlight the shortest routes through the graph if all routes are shown")
parser.add_argument("--normal-ops", action='store_true', help="Show the normal operation graph (apart from embedded normal ops)")
parser.add_argument("--embedded-normal-ops", action='store_true', help="Show normal operation nodes embedded in the attack graph")
parser.add_argument("--external-causes", action='store_true', help="Show the external causes (apart from 'DefaultTW' ones)")
parser.add_argument("--default-tw", action='store_true', help="Show the 'DefaultTW' external causes")
parser.add_argument("--initial-causes", action='store_true', help="Show the initial causes (apart from 'InService' ones)")
parser.add_argument("--in-service", action='store_true', help="Show the 'InService' initial causes")
parser.add_argument("--hide-confusing-misbehaviours", action='store_true', help="Hide misbehaviours relating to inferred assets")
parser.add_argument("--hide-misbehaviours", action='store_true', help="Hide all misbehaviour nodes")
parser.add_argument("--hide-secondary-threats", action="store_true", help="Hide secondary threats in the graph")
parser.add_argument("--constrain-arrows", action='store_true', help="Force the arrows to enter/leave the nodes at the top/bottom (or left/right)")
parser.add_argument("--align-root-causes", action='store_true', help="Align the root causes")
parser.add_argument("--align-target-misbehaviours", action='store_true', help="Align the target misbehaviours")  # TODO: needs to be mutually exclusive with align-root-causes
parser.add_argument("--blobs", action="store_true", help="Show all nodes as circles with no content")
parser.add_argument("--compact", action="store_true", help="Make the plot more compact by reducing margins between nodes")
parser.add_argument("--hide-link-labels", action="store_true", help="Hide the labels on the arrows connecting the nodes")
parser.add_argument("--hide-command", action='store_true', help="Hide the command line from the plot")

parser.add_argument("--likelihood", action='store_true', help="Show the likelihood on each node")
parser.add_argument("--impact", action='store_true', help="Show the impact on each node")
parser.add_argument("--risk", action='store_true', help="Show the risk on each node")
parser.add_argument("--uris", action='store_true', help="Show the URI of each node")
parser.add_argument("--distance-from-root", action='store_true', help="Show the distance from the root cause on a node")
parser.add_argument("--primary-threat-distance", action='store_true', help="Show the number of primary threats needed to get to each node")
parser.add_argument("--attack-graph-controls", action='store_true', help="Show logical expressions for controls that block the attack graph on each node")
parser.add_argument("--threat-graph-controls", action='store_true', help="Show logical expressions for controls that block the threat graph on each node")
parser.add_argument("--attack-graph-control-strategies", action='store_true', help="Show logical expressions for controls strategies that block the attack graph on each node")
parser.add_argument("--threat-graph-control-strategies", action='store_true', help="Show logical expressions for controls strategies that block the threat graph on each node")
parser.add_argument("--threat-description", action='store_true', help="Show the long threat descriptions")
parser.add_argument("--misbehaviour-description", action='store_true', help="Show the long misbehaviour descriptions")
parser.add_argument("--node-titles", action="store_true", help="Show the titles on the nodes")
parser.add_argument("--likelihood-in-description", action="store_true", help="Show the likelihood in the node descriptions")
parser.add_argument("--text-width", metavar="integer", default="60", help="Character-width of the text in nodes")

parser.add_argument("--debug-csv", dest="csv_debug_filename", metavar="filename", help="Filename to dump CSV formatted node information for debugging")
parser.add_argument("--debug-logical-expressions", dest="le_debug_filename", metavar="filename", help="Filename to write logical expressions for target consequences into")

parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)

raw = parser.parse_args()
args = vars(raw)

nq_filename = args["input"]
csv_directory = args["csvs"]
output_filename, output_format = args["output"].split(".")
target_ms_ids = args["misbehaviours"]

domain_misbehaviours_filename = Path(csv_directory) / "Misbehaviour.csv"
domain_trustworthiness_attributes_filename = Path(csv_directory) / "TrustworthinessAttribute.csv"
domain_ca_settings_filename = Path(csv_directory) / "CASetting.csv"
domain_controls_filename = Path(csv_directory) / "Control.csv"
domain_control_strategies_filename = Path(csv_directory) / "ControlStrategy.csv"

# General plot options:
FUTURE_RISK = not args["current_risk"]
LIMIT_LOGIC_TO_SHORTEST_PATH = args["limit_logic"]
HIDE_LONG_ROUTES = not args["all_routes"]
SHOW_NORMAL_OPS = args["normal_ops"]
SHOW_EMBEDDED_NORMAL_OPS = args["embedded_normal_ops"]
SHOW_EXTERNAL_CAUSES = args["external_causes"]
SHOW_DEFAULT_TW = args["default_tw"]
SHOW_INITIAL_CAUSES = args["initial_causes"]
SHOW_IN_SERVICE = args["in_service"]
HIGHLIGHT_SHORT_ROUTES = args["highlight_short_routes"]
HIDE_CONFUSING_MISBEHAVIOURS = args["hide_confusing_misbehaviours"]
HIDE_ALL_MISBEHAVIOURS = args["hide_misbehaviours"]
HIDE_SECONDARY_THREATS = args["hide_secondary_threats"]
ALIGN_ROOT_CAUSES = args["align_root_causes"]
ALIGN_TARGET_MISBEHAVIOURS = args["align_target_misbehaviours"]
PLOT_DIRECTION = args["plot_direction"]
HIDE_COMMAND = args["hide_command"]
CONSTRAIN_ARROWS = args["constrain_arrows"]
HIDE_LINK_LABELS = args["hide_link_labels"]
ADD_ANDS = args["and"]
ADD_ORS = args["or"]

# Node plot options:
TEXT_WIDTH = int(args["text_width"])  # word-wrap limit in nodes
SHOW_DISTANCE_FROM_ROOT = args["distance_from_root"]  # show the distance from the nearest root cause on each node
SHOW_THREAT_DESCRIPTION = args["threat_description"]  # show full threat descriptions
SHOW_MISBEHAVIOUR_DESCRIPTION = args["misbehaviour_description"]  # show full effect descriptions
SHOW_ATTACK_MITIGATION_CS = args["attack_graph_controls"]  # show the attack tree control set mitigation Boolean expression on each node
SHOW_THREAT_MITIGATION_CS = args["threat_graph_controls"]  # show the threat tree control set mitigation Boolean expression on each node
SHOW_ATTACK_MITIGATION_CSG = args["attack_graph_control_strategies"]  # show the attack tree control strategy mitigation Boolean expression on each node
SHOW_THREAT_MITIGATION_CSG = args["threat_graph_control_strategies"]  # show the threat tree control strategy mitigation Boolean expression on each node
SHOW_URI = args["uris"]  # show the URI of a node
SHOW_BLOBS = args["blobs"]
COMPACT = args["compact"]
SHOW_PRIMARY_THREAT_DISTANCE = args["primary_threat_distance"]
SHOW_NODE_TITLES = args["node_titles"]
SHOW_LIKELIHOOD_IN_DESCRIPTION = not args["likelihood_in_description"]
SHOW_LIKELIHOOD = args["likelihood"]  # show the likelihood on each node
SHOW_IMPACT = args["impact"]  # show the impact on each node
SHOW_RISK = args["risk"]  # show the risk on each node

# Rarely required options with no corresponding command line argument:
SHOW_LIKELIHOOD = True  # display each node's likelihood
SHOW_IMPACT = True  # display each Misbehavior node's impact
SHOW_RISK = True  # display each node's (system) risk
SHOW_ROOT_CAUSE = False  # show the root cause of each node
SHOW_ATTACK_TREE = False  # show the attack tree on each node
SHOW_THREAT_TREE = False  # show the threat tree on each node
SHOW_CAUSE_URIS = False  # show the URIs of a node's direct causes
SHOW_CACHE_DEBUG = False  # show the number of visits and results of different types on each node
SHOW_RANK = False  # show the "rank" of each node (useful for debugging)

# Debug options
csv_debug_filename = args["csv_debug_filename"]
le_debug_filename = args["le_debug_filename"]

# Constants to query RDF:
CORE = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/core"
DOMAIN = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain"
SYSTEM = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/system"

HAS_TYPE = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
HAS_ID = URIRef(CORE + "#hasID")
HAS_COMMENT = URIRef("http://www.w3.org/2000/01/rdf-schema#comment")
HAS_LABEL = URIRef("http://www.w3.org/2000/01/rdf-schema#label")

CAUSES_DIRECT_MISBEHAVIOUR = URIRef(CORE + "#causesDirectMisbehaviour")
CAUSES_INDIRECT_MISBEHAVIOUR = URIRef(CORE + "#causesIndirectMisbehaviour")
HAS_SECONDARY_EFFECT_CONDITION = URIRef(CORE + "#hasSecondaryEffectCondition")
AFFECTS = URIRef(CORE + "#affects")
AFFECTED_BY = URIRef(CORE + "#affectedBy")
HAS_ENTRY_POINT = URIRef(CORE + "#hasEntryPoint")
IS_ROOT_CAUSE = URIRef(CORE + "#isRootCause")
APPLIES_TO = URIRef(CORE + "#appliesTo")
LOCATED_AT = URIRef(CORE + "#locatedAt")
HAS_NODE = URIRef(CORE + "#hasNode")
HAS_ASSET = URIRef(CORE + "#hasAsset")
HAS_MISBEHAVIOUR = URIRef(CORE + "#hasMisbehaviour")
HAS_TWA = URIRef(CORE + "#hasTrustworthinessAttribute")
HAS_INFERRED_LEVEL = URIRef(CORE + "#hasInferredLevel")
THREAT = URIRef(CORE + "#Threat")
HAS_LIKELIHOOD = URIRef(CORE + "#hasPrior")
HAS_IMPACT = URIRef(CORE + "#hasImpactLevel")
HAS_RISK = URIRef(CORE + "#hasRisk")
MISBEHAVIOUR_SET = URIRef(CORE + "#MisbehaviourSet")
MITIGATES = URIRef(CORE + "#mitigates")
BLOCKS = URIRef(CORE + "#blocks")
HAS_CONTROL_SET = URIRef(CORE + "#hasControlSet")
HAS_MANDATORY_CONTROL_SET = URIRef(CORE + "#hasMandatoryCS")
CONTROL_SET = URIRef(CORE + "#ControlSet")
HAS_CONTROL = URIRef(CORE + "#hasControl")
IS_PROPOSED = URIRef(CORE + "#isProposed")
CAUSES_THREAT = URIRef(CORE + "#causesThreat")
CAUSES_MISBEHAVIOUR = URIRef(CORE + "#causesMisbehaviour")
IS_EXTERNAL_CAUSE = URIRef(CORE + "#isExternalCause")
IS_INITIAL_CAUSE = URIRef(CORE + "#isInitialCause")
IS_NORMAL_OP = URIRef(CORE + "#isNormalOp")
IS_NORMAL_OP_EFFECT = URIRef(CORE + "#isNormalOpEffect")
PARENT = URIRef(CORE + "#parent")
DUMMY_CSG = "dummy-csg"
DEFAULT_TW_ATTRIBUTE = URIRef(DOMAIN + "#DefaultTW")
IN_SERVICE = URIRef(DOMAIN + "#InService")
INFINITY = 99999999

# The second line of a CSV file often contains default values and if so will include domain#000000
DUMMY_URI = "domain#000000"

def load_domain_misbehaviours(filename):
    """Load misbehaviours from the domain model so that we can use the labels"""
    misbehaviour = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")
        for row in reader:
            if DUMMY_URI in row: continue
            misbehaviour[row[uri_index]] = {}
            misbehaviour[row[uri_index]]["label"] = row[label_index]
            misbehaviour[row[uri_index]]["description"] = row[comment_index]
    return misbehaviour

def load_domain_trustworthiness_attributes(filename):
    """Load trustworthiness attributes from the domain model so that we can use the labels"""
    ta = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")
        for row in reader:
            if DUMMY_URI in row: continue
            ta[row[uri_index]] = {}
            ta[row[uri_index]]["label"] = row[label_index]
            ta[row[uri_index]]["description"] = row[comment_index]
    return ta

def load_domain_controls(filename):
    """Load controls from the domain model so that we can use the labels"""
    control = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        for row in reader:
            if DUMMY_URI in row: continue
            control[row[uri_index]] = {}
            control[row[uri_index]]["label"] = row[label_index]
    return control

def load_domain_control_strategies(filename):
    """Load control strategies from the domain model so that we can use the labels"""
    csg = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        for row in reader:
            if DUMMY_URI in row: continue
            csg[row[uri_index]] = {}
            csg[row[uri_index]]["label"] = row[label_index]
    return csg

def load_domain_ca_settings(filename):
    """Load information from the domain model so that we know which control sets are assertable"""
    settings = {}
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        uri_index = header.index("URI")
        assertable_index = header.index("isAssertable")
        for row in reader:
            if DUMMY_URI in row: continue
            assertable = True if row[assertable_index] == "TRUE" else False
            settings[row[uri_index].split('#')[1]] = assertable
    return settings

def plot_graph(filename, nodes_to_plot, links_to_plot, rank_by_uri, highlighted_nodes):
    """Plot a graph of the attack tree.

    filename: filename to write to
    nodes_to_plot: set of TreeNode objects to include in the plot
    links_to_plot: set of (node, predicate, node) tuples to plot (only those where both ends are in the nodes_to_plot set are used)
    rank_by_uri: dictionary describing the numeric rank of each node using the node.uri as the key
    highlighted_nodes: set of nodes which should be highlighted
    """
    print("Plotting graph "+ filename + "...")

    # the neato engine does a pretty good job but ignores the ranks
    # gv = Digraph(engine="neato")
    # the dot engine uses the rank info provided
    gv = Digraph(engine="dot")
    gv.format = output_format
    gv.attr("node", shape="box")
    gv.attr(overlap="scale")  # "false" is often good but need to use "scale" in Windows because Windows binary does not inlcude necessary lib
    gv.attr(splines="true")  # "true" means arrows avoid nodes (but also means it is not the same style as SSM)
    gv.attr(newrank="true")
    if not COMPACT:
        gv.attr(nodesep="1")
        gv.attr(ranksep="1")
    else:
        gv.attr(nodesep="1")
        gv.attr(ranksep="0.3")
    gv.attr(pagedir="BL")
    gv.attr(rankdir=PLOT_DIRECTION)

    nodes_to_plot = sorted(nodes_to_plot, key=lambda n: n.uri)

    if ALIGN_ROOT_CAUSES or ALIGN_TARGET_MISBEHAVIOURS:
        nodes_by_rank = defaultdict(list)
        for node in nodes_to_plot:
            nodes_by_rank[rank_by_uri.get(node.uri, INFINITY)].append(node)

        ranks = list(nodes_by_rank.keys())
        ranks.sort()
        if ALIGN_TARGET_MISBEHAVIOURS: ranks.reverse()

        node_from_previous = None
        for rank in ranks:
            with gv.subgraph() as sub:
                sub.attr(rank="same")
                for node in nodes_by_rank[rank]:
                    plot_node(sub, node, node in highlighted_nodes, rank)
            node_from_this_rank = nodes_by_rank[rank][0]
            if node_from_previous != None:
                # add an invisible constrained link forcing one rank to be further down the page than the next
                gv.edge(node_from_previous.uri[7:], node_from_this_rank.uri[7:], "RANK", {"constraint": "True", "style": "invis"})
            node_from_previous = node_from_this_rank
        
    else:
        for node in nodes_to_plot:
            plot_node(gv, node, node in highlighted_nodes)

    for link in links_to_plot:
        start_node, predicate, end_node = link
        if start_node not in nodes_to_plot or end_node not in nodes_to_plot:
            continue
        is_from_normal_op = start_node.is_normal_op
        if ALIGN_TARGET_MISBEHAVIOURS:
            is_back_link = rank_by_uri[start_node.uri] <= rank_by_uri[end_node.uri]
        elif ALIGN_ROOT_CAUSES:
            if start_node.is_normal_op and (not end_node.is_normal_op):
                is_back_link = False
            else:
                is_back_link = rank_by_uri[start_node.uri] >= rank_by_uri[end_node.uri]
        else:
            is_back_link = False
        is_highlighted = len(nodes_to_plot) > len(highlighted_nodes) and start_node in highlighted_nodes and end_node in highlighted_nodes
        is_from_external_cause = start_node.is_external_cause
        plot_link(gv, link, is_back_link, is_from_normal_op, is_highlighted, is_from_external_cause)

    gv.body.append('labelloc="b";')

    if not HIDE_COMMAND:
        gv.body.append('label="\n\n{}";'.format(' '.join(sys.argv)))
    # Tip: open PDF of graph in Chrome to avoid locking the file, the press F5 in Chrome to refresh page
    gv.render(filename)

def plot_node(gv, node, is_highlighted=True, rank=None):
    attr = {"style": "filled", "color": "#333333", "margin": "0.3,0.3"}

    uriref = node.uri

    if node.is_logic:
        attr["fillcolor"] = "#65ff65"
        attr["shape"] = "hexagon"
        attr["margin"] = "0.1"
    elif node.is_threat:
        if node.is_normal_op:
            if node.is_initial_cause:
                node_type = "Initial Cause"
                attr["fillcolor"] = "#dddddd"
                attr["penwidth"] = "6"
            else:
                node_type = "Normal Operation"
                attr["fillcolor"] = "#ffffff"
        else:
            if node.is_root_cause:
                node_type = "Root Cause Threat"
                attr["fillcolor"] = "#ff6565"  # ff0000 40% lighter
                attr["penwidth"] = "6"
            else:
                attr["fillcolor"] = "#ff9999"  # ff0000 60% lighter
                if node.is_secondary_threat:
                    node_type = "Secondary Threat"
                    if not HIDE_SECONDARY_THREATS:
                        attr["style"] += ",rounded"
                else:
                    node_type = "Primary Threat"
                    if not HIDE_SECONDARY_THREATS:
                        attr["color"] = "#ff0000"
                        attr["penwidth"] = "4"
            if not is_highlighted:
                attr["fillcolor"] = "#ffe5e5"  # ff0000 90% lighter
    else:
        if node.is_normal_op:
            node_type = "Normal Effect"
            attr["fillcolor"] = "#ffffff"
        else:
            if node.is_external_cause:
                node_type = "External Cause"
                attr["fillcolor"] = "#ffd700"
                attr["penwidth"] = "6"
            else:
                node_type = "Consequence"
                if node.is_target_ms:
                    attr["fillcolor"] = "#ffd700"
                else:
                    attr["fillcolor"] = "#ffef99"  # 60% lighter
                if not is_highlighted:
                    attr["fillcolor"] = "#fffbe5"  # 90% lighter

    if ALIGN_ROOT_CAUSES or ALIGN_TARGET_MISBEHAVIOURS:
        attr["rank"] = str(rank)

    if COMPACT:
        attr["margin"] = "0.1"

    if node.is_logic:
        if node.is_and:
            text = ["AND"]
        else:
            text = ["OR"]
    elif SHOW_BLOBS:
        attr["shape"] = "circle"
        if node.is_threat and not node.is_secondary_threat:
            attr["shape"] = "square"
        # if node.index != None:
        #     text = [str(node.index)]
        # else:
        text = []
    else:
        text = []

        if SHOW_NODE_TITLES:
            text.append("<B>{}</B>".format(node_type))
            
        text.append(textwrap.fill(node.comment, TEXT_WIDTH))

        if (node.is_threat and SHOW_THREAT_DESCRIPTION) or (not node.is_threat and SHOW_MISBEHAVIOUR_DESCRIPTION):
            text.append(textwrap.fill(node.description, TEXT_WIDTH))

        if SHOW_RANK and rank != None:
            text.append("Rank: {}".format(rank))

        if not node.is_external_cause:
            levels = []
            if SHOW_LIKELIHOOD:
                levels.append("Likelihood: {}".format(node.likelihood_text))

            if SHOW_IMPACT and not node.is_threat:
                levels.append("Impact: {}".format(node.impact_text))

            if SHOW_RISK:
                if node.is_threat:
                    prefix = "System"
                else:
                    prefix = "Direct"
                levels.append("{} Risk: {}".format(prefix, node.risk_text))
            text.append("\n".join(levels))

    if SHOW_PRIMARY_THREAT_DISTANCE and not node.is_logic:
        text.append("{}".format(node.min_primary_threat_distance))

    if SHOW_DISTANCE_FROM_ROOT and node.min_distance_from_root > 0 and not node.is_logic:
        text.append("{}/{}".format(node.min_distance_from_root, node.max_distance_from_root))

    if SHOW_ROOT_CAUSE and not node.is_root_cause and not node.is_external_cause and not node.is_initial_cause:
        text.append("Root cause:\n" + str(node.root_cause).replace("\n", "\l") + "\l")

    # Don't show attack tree on normal-ops
    if SHOW_ATTACK_TREE and not node.is_normal_op:
        text.append("Attack tree:\n" + str(node.attack_tree).replace("\n", "\l") + "\l")

    # Don't show attack path mitigation on normal-ops
    if SHOW_ATTACK_MITIGATION_CS and not node.is_normal_op:
        text.append("Controls to block attack:\n" + str(node.attack_tree_mitigation_cs).replace("\n", "\l") + "\l")

    # Don't show attack path mitigation on normal-ops
    if SHOW_ATTACK_MITIGATION_CSG and not node.is_normal_op:
        text.append("Control strategies to block attack:\n" + str(node.attack_tree_mitigation_csg).replace("\n", "\l") + "\l")

    # Don't show threat tree if it's the same as the attack tree (and we're showing that)
    if SHOW_THREAT_TREE and not (SHOW_ATTACK_TREE and str(node.attack_tree) == str(node.threat_tree)):
        text.append("Threat tree:\n" + str(node.threat_tree).replace("\n", "\l") + "\l")

    # Don't show threat path mitigation if it's the same as the attack path mitigation (and we're showing that)
    if SHOW_THREAT_MITIGATION_CS and not (SHOW_ATTACK_MITIGATION_CS and str(node.attack_tree_mitigation_cs) == str(node.threat_tree_mitigation_cs)):
        text.append("Controls to block threat:\n" + str(node.threat_tree_mitigation_cs).replace("\n", "\l") + "\l")

    # Don't show threat path mitigation if it's the same as the attack path mitigation (and we're showing that)
    if SHOW_THREAT_MITIGATION_CSG and not (SHOW_ATTACK_MITIGATION_CSG and str(node.attack_tree_mitigation_csg) == str(node.threat_tree_mitigation_csg)):
        text.append("Control strategies to block threat:\n" + str(node.threat_tree_mitigation_csg).replace("\n", "\l") + "\l")

    if SHOW_CAUSE_URIS:
        # Put parentheses round normal-ops
        text.append("Direct causes:")
        # sort the parents so that we get a consistent comparable plot
        for direct_cause_uri in sorted(node.direct_cause_uris):
            # TODO: remove use of global threat_tree here
            if not threat_tree[direct_cause_uri].is_normal_op:
                text.append(get_comment(direct_cause_uri.split('#')[1]))
            else:
                text.append("(" + get_comment(direct_cause_uri.split('#')[1]) + ")")

    if SHOW_CACHE_DEBUG:
        text.append("Cache hits / Visits: {} / {}".format(node.cache_hit_visits, node.visits))
        text.append("Cause / No cause: {} / {}".format(node.cause_visits, node.no_cause_visits))

    if SHOW_URI:
        text.append("<I>" + str(uriref).split('#')[1] + "</I>")

    text = "<BR/><BR/>".join(text)
    text = text.replace("\n", "<BR/>")
    text = text.replace("\l", '<BR ALIGN="LEFT"/>')
    
    text = "<" + text + ">"
    gv.node(uriref[7:], text, **attr)

def plot_link(gv, link, is_back_link, is_from_normal_op, is_highlighted, is_from_external_cause):
    start_uri = link[0].uri
    if not HIDE_LINK_LABELS:
        label = link[1]
    else:
        label = ""
    end_uri = link[2].uri

    attr = {"fontcolor": "black", "color": "black", "style": "solid", "penwidth": "3"}
    if CONSTRAIN_ARROWS:
        if PLOT_DIRECTION == "TB":
            attr["tailport"] = "s"
            attr["headport"] = "n"
        elif PLOT_DIRECTION == "BT":
            attr["tailport"] = "n"
            attr["headport"] = "s"
        elif PLOT_DIRECTION == "LR":
            attr["tailport"] = "e"
            attr["headport"] = "w"
        elif PLOT_DIRECTION == "RL":
            attr["tailport"] = "w"
            attr["headport"] = "e"

    if is_from_normal_op or is_from_external_cause:
        attr["style"] = "dashed"
        attr["color"] = "gray"
    if is_back_link:
        attr["color"] = "red"
    if is_highlighted:
        attr["penwidth"] = "8"

    gv.edge(start_uri[7:], end_uri[7:], label, **attr)

def un_camel_case(text):
    text = text.strip()
    if text == "": return "****"
    text = text.replace("TW", "Trustworthiness")
    if text[0] == "[":
        return text
    else:
        text = re.sub('([a-z])([A-Z])', r'\1 \2', text)
        text = text.replace("Auth N", "AuthN")  # re-join "AuthN" into one word
        text = re.sub('(AuthN)([A-Z])', r'\1 \2', text)
        text = text.replace("Io T", "IoT")  # re-join "IoT" into one word
        text = re.sub('(IoT)([A-Z])', r'\1 \2', text)
        text = re.sub('([A-Z]{2,})([A-Z][a-z])', r'\1 \2', text)  # split out e.g. "PIN" or "ID" as a separate word
        text = text.replace('BIO S', 'BIOS ')  # one label is "BIOSatHost"
        return text

def get_comment(uriref):
    if (uriref, HAS_TYPE, MISBEHAVIOUR_SET) in graph:
        return get_ms_comment(uriref)
    elif (uriref, HAS_TYPE, CONTROL_SET) in graph:
        return get_cs_comment(uriref)
    elif (get_is_threat(uriref)):
        return get_threat_comment(uriref)
    elif DUMMY_CSG in str(uriref):
        return get_csg_comment(uriref)

    if str(uriref).startswith("http://"):
        label = graph.label(subject=uriref, default=None)

        if label is not None:
            return label

        if str(uriref).startswith(CORE):
            label = "core" + str(uriref)[len(CORE):]
        elif str(uriref).startswith(DOMAIN):
            label = "domain" + str(uriref)[len(DOMAIN):]

    else:
        label = str(uriref)

    return label

def _get_threat_comment(uriref):
    """Return the first part of the threat description (up to the colon)"""
    comment = graph.value(subject=uriref, predicate=HAS_COMMENT)
    quote_counter = 0
    char_index = 0
    # need to deal with the case where there is a colon in a quoted asset label
    while (comment[char_index] != ":" or quote_counter % 2 != 0):
        if comment[char_index] == '"':
            quote_counter += 1
        char_index += 1
    comment = comment[0:char_index]
    return comment

def get_threat_comment(uriref):
    """Return the first part of the threat description (up to the colon) and add in the likelihood if so configured"""
    comment = _get_threat_comment(uriref)
    comment = comment.replace('re-disabled at "Router"', 're-enabled at "Router"')  # hack that is necessary to correct an error in v6a3-1-4 for the overview paper system model
    if not SHOW_LIKELIHOOD_IN_DESCRIPTION:
        return comment
    else:
        likelihood = un_camel_case(get_likelihood_text(uriref))
        return '{} likelihood of: {}'.format(likelihood, comment)

def get_threat_description(uriref):
    """Return the longer description of a threat (after the colon)"""
    short_comment = _get_threat_comment(uriref)
    comment = graph.value(subject=uriref, predicate=HAS_COMMENT)
    comment = comment[len(short_comment) + 1:]  # remove the short comment from the start
    comment = comment.lstrip()  # there is conventionally a space after the colon
    char = comment[0]
    return char.upper() + comment[1:]  # uppercase the first word

def get_ms_comment(uriref):
    """Return a short description of a misbehaviour"""
    likelihood = un_camel_case(get_likelihood_text(uriref))
    consequence = get_ms_label(uriref)
    asset_uri = graph.value(subject=uriref, predicate=LOCATED_AT)
    asset = graph.label(asset_uri)
    aspect = None
    if consequence.startswith("LossOf"):
        aspect = un_camel_case(consequence[6:])
        consequence = "loses"
    elif consequence.startswith("Loss Of"):
        aspect = un_camel_case(consequence[7:])
        consequence = "loses"
    elif consequence.startswith("Not"):
        aspect = un_camel_case(consequence[3:])
        consequence = "is not"
    if aspect != None:
        if not SHOW_LIKELIHOOD_IN_DESCRIPTION and uriref not in target_ms_uris:
            return '"{}" {} {}'.format(un_camel_case(asset), consequence, aspect)
        else:
            return '{} likelihood that "{}" {} {}'.format(likelihood, un_camel_case(asset), consequence, aspect)
    else:
        if not SHOW_LIKELIHOOD_IN_DESCRIPTION and uriref not in target_ms_uris:
            return '{} at {}'.format(un_camel_case(consequence), un_camel_case(asset))
        else:
            return '{} likelihood of: {} at {}'.format(likelihood, un_camel_case(consequence), un_camel_case(asset))

def get_ms_description(uriref):
    """Return a long description of a misbehaviour"""
    misbehaviour = graph.value(uriref, HAS_MISBEHAVIOUR)
    try:
        return misbehaviours[misbehaviour.split('/')[-1]]["description"]
    except:
        # might get here if the domain model CSVs are the wrong ones
        logging.warning("No MS description for " + str(uriref))
        return "**MS description**"

def get_ms_label(uriref):
    """Return a misbehaviour label"""
    misbehaviour = graph.value(uriref, HAS_MISBEHAVIOUR)
    try:
        return misbehaviours[misbehaviour.split('/')[-1]]["label"]
    except:
        # might get here if the domain model CSVs are the wrong ones
        logging.warning("No MS label for " + str(uriref))
        return "**MS label**"

def get_twas_description(uriref):
    """Return a long description of a TWAS"""
    twa = graph.value(uriref, HAS_TWA)
    try:
        return trustworthiness_attributes[twa.split('/')[-1]]["description"]
    except:
        # might get here if the domain model CSVs are the wrong ones
        logging.warning("No TWAS description for " + str(uriref))
        return "**TWAS description**"

def get_twas_comment(uriref):
    """Return a short description of a TWAS"""
    tw_level = un_camel_case(get_trustworthiness_text(uriref))
    twa = get_twas_label(uriref)
    asset_uri = graph.value(subject=uriref, predicate=LOCATED_AT)
    asset = graph.label(asset_uri)
    return '{} of {} is {}'.format(un_camel_case(twa), asset, tw_level)

def get_twas_label(uriref):
    """Return a TWAS label"""
    twa = graph.value(uriref, HAS_TWA)
    try:
        return trustworthiness_attributes[twa.split('/')[-1]]["label"]
    except:
        # might get here if the domain model CSVs are the wrong ones
        logging.warning("No TWAS label for " + str(uriref))
        return "**TWAS label**"

def get_cs_comment(cs_uri):
    control_uri = graph.value(cs_uri, HAS_CONTROL)
    control_label = un_camel_case(controls[control_uri.split('/')[-1]]["label"])
    asset_uri = graph.value(cs_uri, LOCATED_AT)
    asset_label = graph.value(asset_uri, HAS_LABEL)
    if asset_label[0] != "[": asset_label = '"' + asset_label + '"'
    return control_label + " at " + asset_label

def get_csg_comment(dummy_csg_uri):
    # TODO: change this to not use the MyControlStrategy and just use the CSG directly
    my_csg = MyControlStrategy.get_by_dummy_uriref(dummy_csg_uri)
    # cs_comment = "AND(" + ", ".join([get_cs_comment(cs) for cs in my_csg.inactive_control_set_uris]) + ")"
    # comment = "{}: {}".format(my_csg.label, cs_comment)
    # comment = "{}: {}".format(my_csg.label, my_csg.description)
    # comment = "{}".format(my_csg.label)
    asset_labels = list(set(get_csg_asset_labels(my_csg)))  # get unique set of asset labels the CSG involves (whether proposed or not)
    asset_labels = [abbreviate_asset_label(label) for label in asset_labels]
    asset_labels.sort()
    comment = "{} ({})".format(my_csg.label, ", ".join(asset_labels))
    return comment

def abbreviate_asset_label(label):
    if label.startswith("[ClientServiceChannel:"):
        # Example input:
        # [ClientServiceChannel:(Philip's PC)-(Philip's Web Browser)-(Web Server)-Website-[NetworkPath:Internet-[NetworkPath:(Shop DMZ)]]]
        bits = label.split("-")
        return "[ClientServiceChannel:" + bits[1] + "-" + bits[3]
    return label

def make_symbol(uriref):
    """Make a symbol from the URI fragment for us in logical expressions"""
    return symbol(uriref.split('#')[1])

def get_comment_from_match(frag_match):
    return get_comment(URIRef(SYSTEM + "#" + frag_match.group()[8:-2]))

class LogicalExpression():
    """Represents a Boolean expression using URI fragments as the symbols."""
    def __init__(self, cause_list, all_required=True):
        """Arguments:

        cause_list: list
                can be a mixture of None, LogicalExpression and symbol
        all_required: Boolean
                whether all the parts of the expression are required (resulting in an AND) or not (giving an OR)
        """
        all_causes = []
        for cause in cause_list:
            if isinstance(cause, LogicalExpression):
                all_causes.append(cause.cause)
            else:
                all_causes.append(cause)

        all_causes = [c for c in all_causes if c is not None]

        if len(all_causes) == 0:
            self.cause = None
        elif len(all_causes) == 1:
            self.cause = all_causes[0]
        else:
            if all_required:
                self.cause = AND(*all_causes).simplify()
            else:
                self.cause = OR(*all_causes).simplify()

    def __str__(self):
        return self.pretty_print()

    def __eq__(self, other):
        return self.cause == other.cause

    def __hash__(self) -> int:
        return hash(self.cause)

    @property
    def uris(self):
        return set([URIRef(SYSTEM + "#" + str(symbol)) for symbol in self.cause.get_symbols()])

    def pretty_print(self, max_complexity=30):
        if self.cause is None:
            return "-None-"
        cause_complexity = str(self.cause.args).count("Symbol")
        if cause_complexity <= max_complexity:
            cause = algebra.dnf(self.cause.simplify())
            symb = re.compile(r'Symbol\(\'.*?\'\)')
            cause = symb.sub(get_comment_from_match, cause.pretty())
        else:
            cause = "Complexity: " + str(cause_complexity)
        return cause

class TreeTraversalError(Exception):
    """Some error when recursing down the tree"""
    def __init__(self, loopback_node_uris: set = None) -> None:
        if loopback_node_uris is None: loopback_node_uris = set()
        self.loopback_node_uris = loopback_node_uris

class ThreatTree():
    """The container for a set of TreeNodes"""
    def __init__(self, target_uris=None, is_future_risk=True, shortest_path=False):
        """
        Parameters
        ----------
        target_uris : list of URIRef
            describes the misbehaviours that we want to know the threat trees for
        is_future_risk : bool, optional
            whether to do a future or current risk analysis (affects which control strategies are considered)
        shortest_path : bool, optional
            if True then only the TreeNodes on the shortest paths are included in the ThreatTree
        """
        self._node_by_uri = {}
        self.target_uris = target_uris
        self.is_future_risk = is_future_risk
        self.bounding_urirefs = None
        if not shortest_path:
            logging.info("Running backtrace")
            self._backtrace(compute_logic=True)
            logging.info("Tree has " + str(len(self.nodes)) + " nodes")
        else:
            # If the shortest path is required then we get the URIRefs of the shortest path nodes from the first pass at the ThreatTree
            # then discard all TreeNodes and create a new ThreatTree which is bounded by the shortest path URIRefs.
            logging.info("Running first backtrace")
            self._backtrace(compute_logic=False)
            logging.info("Tree has " + str(len(self.nodes)) + " nodes")
            self.bounding_urirefs = set([node.uri for node in self.shortest_path_nodes])
            self._node_by_uri = {}
            logging.info("Running second backtrace, bounded by " + str(len(self.bounding_urirefs)) + " nodes")
            self._backtrace(compute_logic=True)
            logging.info("Tree has " + str(len(self.nodes)) + " nodes")


    def __getitem__(self, uri):
        return self._node_by_uri[uri]

    def get_or_create_node(self, uri):
        if uri not in self._node_by_uri:
            self._node_by_uri[uri] = TreeNode(uri, self)
        return self._node_by_uri[uri]

    def _backtrace(self, compute_logic=True):
        for target_uri in self.target_uris:
            node = self.get_or_create_node(target_uri)
            node.is_target_ms = True
            logging.info("Making tree for " + str(node.uri))
            node.backtrace(compute_logic=compute_logic)

    @property
    def nodes(self):
        # Don't return the nodes that are in the error state
        return [node for node in self._node_by_uri.values() if not node.not_a_cause]

    @property
    def uris(self):
        # Don't return the nodes that are in the error state
        return [uri for uri in self._node_by_uri.keys() if not self._node_by_uri[uri].not_a_cause]

    @property
    def root_causes(self):
        uris = set()
        for node in self.nodes:  # Using property
            if node.is_root_cause:
                uris.add(node.uri)
        return uris

    @property
    def external_causes(self):
        uris = set()
        for node in self.nodes:
            if node.is_external_cause:
                uris.add(node.uri)
        return uris

    @property
    def initial_causes(self):
        uris = set()
        for node in self.nodes:
            if node.is_initial_cause:
                uris.add(node.uri)
        return uris

    @property
    def normal_operations(self):
        uris = set()
        for node in self.nodes:
            if node.is_normal_op:
                uris.add(node.uri)
        return uris

    def add_max_distance_from_target(self, uriref, current_path=None):
        """Find the maximum distance from a target URI (useful to space out nodes for plotting)."""
        if current_path == None:
            current_path = ()
        # Using a tuple for current_path to ensure that when we change it we make a copy so that the addition is undone when the recursion unwinds
        current_path = current_path + (uriref,)
        current_node = self._node_by_uri[uriref]
        target_uriref = current_path[0]
        current_distance = current_node.max_distance_from_target_by_target.get(target_uriref, -1)
        current_node.max_distance_from_target_by_target[target_uriref] = max(current_distance, len(current_path) - 1)  # start at 0
        for cause_uriref in current_node.direct_cause_uris:
            # there can be loops in the "tree" so have to make sure we don't follow one
            if cause_uriref not in current_path:
                self.add_max_distance_from_target(cause_uriref, current_path)

    # def get_nodes_in_target_tree(self, target_uriref):
        #TODO: filter self.nodes to find those where max_distance_from_target_by_target has target_uriref as a key

    @property
    def shortest_path_nodes(self):
        """Return the set of nodes that are on the shortest path(s)."""
        # The strategy is to start with all the nodes and remove nodes where none of the children are further away from the root cause, or where there are no children.
        # Each pass through the nodes we look at each node's causes, therefore, if a node is not the cause of another then it gets removed (so dead branches are pruned node by node).
        # We define "good nodes" to be cause nodes which have at least one child further away than (or same distance as) the node, remove the others and iterate until no change.
        # As this is using the min_primary_threat_distance we need to accept distance equality as good.
        short_path_nodes = set(self.nodes)
        while True:
            good_nodes = set([self[target_ms_uri] for target_ms_uri in self.target_uris])  # put these in because they are not anything's cause
            for node in short_path_nodes:
                for cause_node in [self[cause_uri] for cause_uri in node.direct_cause_uris]:
                    # Don't discard causes of threats (or, equivalently, ANDs) as they are all needed regardless of route taken to get to them
                    if node.is_threat or node.is_and:
                        good_nodes.add(cause_node)
                    else:
                        d_cause = cause_node.min_primary_threat_distance
                        d_node = node.min_primary_threat_distance
                        if d_cause is None or d_node is None:
                            logging.error('node {} [{}]\n  cause {} [{}]'.format(node.uri.split('#')[1], d_node, cause_node.uri.split('#')[1], d_cause))
                        elif d_cause <= d_node:
                            good_nodes.add(cause_node)
            if len(good_nodes & short_path_nodes) < len(short_path_nodes):
                short_path_nodes = good_nodes & short_path_nodes
            else:
                break
        return short_path_nodes

    @property
    def attack_graph_mitigation_csg(self):
        return LogicalExpression([self[uri].attack_tree_mitigation_csg for uri in self.target_uris], all_required=True)

    @property
    def attack_graph_mitigation_cs(self):
        return LogicalExpression([self[uri].attack_tree_mitigation_cs for uri in self.target_uris], all_required=True)
    
    @property
    def threat_graph_mitigation_csg(self):
        return LogicalExpression([self[uri].threat_tree_mitigation_csg for uri in self.target_uris], all_required=True)

    @property
    def threat_graph_mitigation_cs(self):
        return LogicalExpression([self[uri].threat_tree_mitigation_cs for uri in self.target_uris], all_required=True)
    
    def add_node_indices(self, i=0, node=None):
        if node == None:
            for root_uri in self.root_causes:
                i = self.add_node_indices(i, self[root_uri])
        else:
            if not node.index:
                node.index = i
                logging.debug("{}|{}".format(i, node.comment))
                i += 1
                for child_uri in node.direct_effect_uris:
                    i = self.add_node_indices(i, self[child_uri])
        return i

# TODO: remove this class
# It used to be the case that there were multiple CSG URIs generated during validation which all were essentially the same (comprising the same group of ControlSets).
# This class maps from the model's CSG URIs to URIs that do not have this duplication issue.
# The validation process was fixed a while ago so this class is no longer required.
class MyControlStrategy():

    object_by_description = {}
    object_by_dummy_uriref = {}

    def __init__(self, description, original_uriref, dummy_uriref):
        self.description = description
        self.original_uriref = original_uriref
        self.uriref = dummy_uriref
        domain_csg_uriref = graph.value(original_uriref, PARENT)
        self.label = un_camel_case(control_strategies[domain_csg_uriref.split('/')[-1]]["label"])
        self.inactive_control_set_uris = get_csg_inactive_control_set_uris(original_uriref)

    @classmethod
    def get_or_create_csg(cls, original_uriref):
        description = str(graph.value(original_uriref, HAS_COMMENT))
        if description in cls.object_by_description:
            return cls.object_by_description[description]
        else:
            dummy_uriref = URIRef(SYSTEM + '#' + DUMMY_CSG + "-" + str(len(MyControlStrategy.object_by_description)))
            cs = MyControlStrategy(description, original_uriref, dummy_uriref)
            cls.object_by_description[description] = cs
            cls.object_by_dummy_uriref[dummy_uriref] = cs
            return cs

    @classmethod
    def get_by_dummy_uriref(cls, dummy_uriref):
        return cls.object_by_dummy_uriref[dummy_uriref]

class TreeNode():
    """Represents a Threat or a Misbehaviour."""
    # TODO: consider whether it would be better to split out Threat and Misbehaviour into subclasses.
    def __init__(self, uri, nodes):
        self.uri = uri
        self.nodes = nodes  # collection it belongs to
        self.is_target_ms = False

        self.control_strategies = self._get_control_strategies()
        self.controls = self._get_controls()
        self.uri_symbol = make_symbol(self.uri)

        # this is all the direct causes
        all_direct_cause_uris = self._get_all_direct_cause_uris()
        # if the containing ThreatTree defines a bound on the nodes to explore then we apply it here by discarding parents not in the bounding_urirefs set
        if self.nodes.bounding_urirefs is not None:
            self.all_direct_cause_uris = set(all_direct_cause_uris) & self.nodes.bounding_urirefs
        else:
            self.all_direct_cause_uris = set(all_direct_cause_uris)

        # these represent the causes/effects which are part of the attack tree this Node is a member of:
        self.direct_cause_uris = set()
        self.direct_effect_uris = set()

        self.max_distance_from_root_by_cause = {}  # keyed by root cause logical expression
        self.min_distance_from_root_by_cause = {}  # keyed by root cause logical expression
        self.max_distance_from_target_by_target = {}  # keyed by target MS

        # LogicalExpressions to record the tree data:
        self.attack_tree_mitigation_cs = None
        self.threat_tree_mitigation_cs = None
        self.attack_tree_mitigation_csg = None
        self.threat_tree_mitigation_csg = None
        self.attack_tree = None
        self.threat_tree = None
        self.root_cause = None

        self.cannot_be_caused = False  # Flag for nodes that cannot be caused because they cause themselves
        self.not_a_cause = True  # Assume the node is not a cause no matter what path taken, unless we find otherwise

        # counters to see what's going on with the caching:
        self.visits = 0
        self.cache_hit_visits = 0
        self.cause_visits = 0
        self.no_cause_visits = 0

        # cached results:
        self.cause_results = []
        self.no_cause_results = []

        self.index = None  # Node index used for plotting in "--blobs" mode
        self.min_primary_threat_route = None  # minimum set of primary threats you have to go through to get to the node

    def __str__(self):
        return "TreeNode: {}\n  ID: {}\n  Comment: {}\n  {} direct causes, {} direct effects".format(
            str(self.uri), id(self), self.comment, len(self.direct_cause_uris), len(self.direct_effect_uris))

    @property
    def likelihood_number(self):
        return get_likelihood_number(self.uri)

    @property
    def likelihood_text(self):
        return get_likelihood_text(self.uri)

    @property
    def impact_text(self):
        return get_impact_text(self.uri)
    
    @property
    def risk_text(self):
        return get_risk_text(self.uri)

    @property
    def is_normal_op(self):
        return get_is_normal_op(self.uri)

    @property
    def is_root_cause(self):
        return get_is_root_cause(self.uri)

    @property
    def is_threat(self):
        return get_is_threat(self.uri)

    @property
    def is_secondary_threat(self):
        return get_is_secondary_threat(self.uri)

    @property
    def is_primary_threat(self):
        return get_is_primary_threat(self.uri)

    @property
    def is_external_cause(self):
        return get_is_external_cause(self.uri)

    @property
    def is_initial_cause(self):
        return get_is_initial_cause(self.uri)

    @property
    def is_misbehaviour_set(self):
        return get_is_misbehaviour_set(self.uri)

    @property
    def is_and(self):
        return self.uri.endswith("-AND")

    @property
    def is_or(self):
        return self.uri.endswith("-OR")

    @property
    def is_logic(self):
        return self.is_and or self.is_or

    @property
    def min_primary_threat_distance(self):
        return len(self.min_primary_threat_route)

    @property
    def comment(self):
        if self.is_threat:
            return get_threat_comment(self.uri)
        elif self.is_misbehaviour_set:
            return get_ms_comment(self.uri)
        else:
            return get_twas_comment(self.uri)

    @property
    def description(self):
        if self.is_threat:
            return get_threat_description(self.uri)
        elif self.is_misbehaviour_set:
            return get_ms_description(self.uri)
        else:
            return get_twas_description(self.uri)

    @property 
    def max_distance_from_target(self):
        try:
            # Probably all nodes should have a distance or should have been deleted
            # Some seem to be unreachable from the target so the next line gives an error
            d = max(self.max_distance_from_target_by_target.values())
        except:
            d = -1
        return d

    @property 
    def min_distance_from_root(self):
        return min(self.min_distance_from_root_by_cause.values())

    @property 
    def max_distance_from_root(self):
        return max(self.max_distance_from_root_by_cause.values())

    def _get_control_strategies(self):
        if not self.is_threat:
            return None
        else:
            control_strategies = get_threat_inactive_control_strategies(self.uri, self.nodes.is_future_risk)
            # TODO: change this to just make_symbol(csg) when removing MyControlStrategy class
            control_strategy_symbols = [make_symbol(csg.uriref) for csg in control_strategies]
            return LogicalExpression(control_strategy_symbols, all_required=False)

    def _get_controls(self):
        if not self.is_threat:
            return None
        else:
            # The LogicalExpression for the controls that will mitigate a threat is:
            # OR(the control strategy expressions)

            # The LogicalExpression for a control strategy is:
            # AND(the control strategy's inactive controls)

            # So we will end up with something like:
            # OR(AND(c1, c2), AND(c3), AND(c1, c4))

            control_strategies = []
            for csg_uri in get_threat_control_strategy_uris(self.uri, self.nodes.is_future_risk):
                csets = get_csg_inactive_control_set_uris(csg_uri)
                control_set_symbols = [make_symbol(cs) for cs in csets]
                control_strategies.append(LogicalExpression(control_set_symbols, all_required=True))
            return LogicalExpression(control_strategies, all_required=False)

    def _get_all_direct_cause_uris(self):
        if (self.uri.endswith("-AND")):
            # then we're at an AND node and need to return the direct causes of the threat that we're the parent of
            threat_uri = URIRef(self.uri[:-4])
            return get_threat_direct_cause_uris(threat_uri)
        elif (self.uri.endswith("-OR")):
            # then we're at an OR node and need to return the direct causes of the misbehaviour that we're the parent of
            misbehaviour_uri = URIRef(self.uri[:-3])
            return get_misbehaviour_direct_cause_uris(misbehaviour_uri)
        elif self.is_threat:
            causes = get_threat_direct_cause_uris(self.uri)
            if ADD_ANDS and len(causes) > 1:
                # return an AND node
                return [self.uri + "-AND"]
            else:
                return causes
        else:
            causes = get_misbehaviour_direct_cause_uris(self.uri)
            if ADD_ORS and len(causes) > 1:
                # return an OR node
                return [self.uri + "-OR"]
            else:
                return causes

    def add_direct_cause_uris(self, uris):
        self.direct_cause_uris |= uris
        for cause_uri in uris:
            self.nodes[cause_uri]._add_direct_effect_uri(self.uri)

    # don't call this one directly, use add_direct_cause_uris()
    def _add_direct_effect_uri(self, uri):
        self.direct_effect_uris.add(uri)

    @property
    def threatened_asset_uris(self):
        if not self.is_threat:
            return [get_misbehaviour_location_uri(self.uri)]
        else:
            asset_uris = []
            for misbehaviour_uri in self.direct_effect_uris:
                asset_uris.append(get_misbehaviour_location_uri(misbehaviour_uri))
            return asset_uris

    @property
    def involved_asset_uris(self):
        if self.is_threat:
            return get_threat_involved_asset_uris(self.uri)
        else:
            return []

    def backtrace(self, current_path=None, compute_logic=True):
        if current_path is None:
            current_path = set()
        logging.debug("  " * len(current_path) + "  Starting backtrace for {} (current path length {})".format(str(self.uri).split('#')[1], str(len(current_path))))
        current_path = set(current_path)  # Make a copy of the set then add self
        current_path.add(self.uri)

        self.visits += 1

        # check the cached results
        if self.cannot_be_caused:
            # If this node is unreachable regardless of path taken to it
            # TODO: this can just be done with zero-length loopback_node_uris result in no_cause_results
            self.cache_hit_visits += 1
            logging.debug("  " * len(current_path) + "  Cannot ever be caused")
            raise TreeTraversalError()

        for result in self.no_cause_results:
            # The loopback nodes are the reasons the node was rejected when previously visited. They were causes of the node that were also on the path to the node.
            # If the current path to this node contains all the previous loopback nodes then there's no point searching the causes again.
            if len(current_path.intersection(result['loopback_node_uris'])) == len(result['loopback_node_uris']):
                self.cache_hit_visits += 1
                logging.debug("  " * len(current_path) + "  Cache hit, cannot be caused")
                raise TreeTraversalError(result['loopback_node_uris'])
        
        valid_caches = []
        for result in self.cause_results:
            # If we have previously found any way for this node to be caused that does not intersect with the current path to the node then we know the cached result will be okay, so could use it.
            # This would mean that we are not looking again when we might be and therefore can miss some other good path.
            # If on a previous occasion we rejected a route because it intersected with the path then there will be some loopback_nodes. If any of the loopback_nodes are not on the current_path then there may be another route to be found.

            if len(current_path.intersection(result['all_cause_uris'])) == 0:
                # then the cached cause will still work
                valid_caches.append(result)

        if len(valid_caches):
            use_cache = True
            for result in valid_caches:
                if len(current_path.intersection(result['loopback_node_uris'])) == len(result['loopback_node_uris']):
                    # then the current path has all the loopback_nodes of the cached result so would behave the same
                    pass
                else:
                    # then in this case there is more to explore
                    logging.debug("  " * len(current_path) + "  Cache hit: node can be caused, but more to explore")
                    use_cache = False
                    break

            if use_cache:
                self.cache_hit_visits += 1
                logging.debug("  " * len(current_path) + "  Cache hit, node can be caused, cache can be used")
                return result

        # store data from this visit to the node
        parent_min_distances_from_root = []
        parent_max_distances_from_root = []
        parent_root_causes = []
        parent_attack_mitigations_cs = []
        parent_threat_mitigations_cs = []
        parent_attack_mitigations_csg = []
        parent_threat_mitigations_csg = []
        parent_attack_trees = []
        parent_threat_trees = []
        parent_primary_threat_routes = []
        valid_parent_uris = set()
        loopback_node_uris = set()  # nodes that cause a failure because they are on the current path
        all_cause_uris = set()
        primary_threat_route = set()

        try:
            if len(self.all_direct_cause_uris) == 0:
                # This will be top of tree misbehaviours (normal-op, external cause). Not root causes as they have parents in normal-ops.
                # TODO: can this just move to the end of the function?
                logging.debug("  " * len(current_path) + "  No direct causes")
                min_distance_from_root = -1
                max_distance_from_root = -1
                root_cause = LogicalExpression([make_symbol(self.uri)])
                if self.is_threat:
                    logging.error("**** ERROR: There should not be a threat with no parents!: " + str(self.uri).split('#')[1])
                    raise Exception()  # TODO: put error in exception and choose a better Exception class
                else:
                    attack_mitigated_by_cs = None
                    threat_mitigated_by_cs = None
                    attack_mitigated_by_csg = None
                    threat_mitigated_by_csg = None
                    attack_tree = None
                    threat_tree = None

            elif self.is_threat or self.is_and:
                if len(self.all_direct_cause_uris & current_path) > 0:
                    # For a threat we require all parents.
                    # If even one is on the current path then the threat is triggered by its own consequence which is useless.
                    logging.debug("  " * len(current_path) + "  ** threat {} is directly dependent on its own consequence: {}".format(str(self.uri).split('#')[1], str([str(u).split('#')[1] for u in (self.all_direct_cause_uris & current_path)])))
                    raise TreeTraversalError(self.all_direct_cause_uris & current_path)

                sorted_causes = sorted(list(self.all_direct_cause_uris))
                logging.debug("  " * len(current_path) + "  " + str(len(sorted_causes)) + " direct causes of threat")
                for parent_uri in sorted_causes:
                    parent = self.nodes.get_or_create_node(parent_uri)
                    try:
                        p_result = parent.backtrace(current_path, compute_logic)
                    except TreeTraversalError as error:
                        logging.debug("  " * len(current_path) + "  ** threat {} has invalid direct cause: {}".format(str(self.uri).split('#')[1], str(parent_uri).split('#')[1]))
                        loopback_node_uris |= error.loopback_node_uris
                        # loopback_node_uris.add(parent_uri)
                        # TODO: At this point, if another parent has previously successfully been backtraced, then that parent will be left hanging with no direct_effects set as this node is found to be invalid. We need to remove these hanging nodes here or later.
                        raise TreeTraversalError(loopback_node_uris)
                    else:
                        # TODO: this clause only needs executing (for each parent) if all the threat's parents are valid.
                        # We could collect all the p_results from the try block and then iterate through them instead of executing immediately.
                        valid_parent_uris.add(parent_uri)
                        loopback_node_uris |= p_result['loopback_node_uris']
                        all_cause_uris |= p_result['all_cause_uris']
                        if (self.is_normal_op == parent.is_normal_op) and not parent.is_external_cause:  # Fully in one region or the other
                            parent_min_distances_from_root.append(p_result['min_distance'])
                            parent_max_distances_from_root.append(p_result['max_distance'])
                            parent_root_causes.append(p_result['root_cause'])

                        parent_primary_threat_routes.append(p_result['primary_threat_route'])

                        if compute_logic:
                            p_attack_mitigation_cs, p_threat_mitigation_cs, p_attack_mitigation_csg, p_threat_mitigation_csg, p_attack_tree, p_threat_tree = p_result['data']
                            parent_threat_mitigations_cs.append(p_threat_mitigation_cs)  # Entire path
                            parent_threat_mitigations_csg.append(p_threat_mitigation_csg)  # Entire path
                            parent_threat_trees.append(p_threat_tree)
                            if not parent.is_normal_op and not parent.is_external_cause:
                                parent_attack_mitigations_cs.append(p_attack_mitigation_cs)  # Just attack path
                                parent_attack_mitigations_csg.append(p_attack_mitigation_csg)  # Just attack path
                                parent_attack_trees.append(p_attack_tree)

                if len(parent_root_causes) == 0:
                    # Then this is a root cause threat
                    parent_min_distances_from_root = [-1]
                    parent_max_distances_from_root = [-1]
                    parent_root_causes.append(LogicalExpression([make_symbol(self.uri)]))

                # The root cause of a threat is all (AND) of the root causes of its parents
                root_cause = LogicalExpression(parent_root_causes, all_required=True)

                # Take the union of routes
                for route in parent_primary_threat_routes:
                    primary_threat_route |= route
                # Add self to primary threat route if self is primary threat
                if self.is_primary_threat and not self.is_normal_op:
                    primary_threat_route.add(self)

                # The distance from a root cause therefore is the maximum of the parent distances + 1
                # However, we don't want to count secondary threats or logic nodes in the distance as they are not "real" steps
                if self.is_secondary_threat or self.is_and:
                    # Because a threat is caused by all parents, it's still a "max" here
                    min_distance_from_root = max(parent_min_distances_from_root)
                    max_distance_from_root = max(parent_max_distances_from_root)
                else:
                    # "max" + 1 for a primary threat
                    min_distance_from_root = max(parent_min_distances_from_root) + 1
                    max_distance_from_root = max(parent_max_distances_from_root) + 1

                logging.debug("  " * len(current_path) + "  Finished looking at threat causes for {} (min: {}, max: {}, {} valid parents: {})".format(str(self.uri).split('#')[1], str(min_distance_from_root), str(max_distance_from_root), str(len(valid_parent_uris)), str([str(u).split('#')[1] for u in valid_parent_uris])))

                if compute_logic:
                    # The attack/threat tree is
                    # AND(
                    #   the threat itself
                    #   all the parent threat tree
                    # )
                    if not self.is_normal_op:
                        # If this threat (self) is on the attack path then it can itself be a mitigation on the attack_path
                        parent_attack_trees.append(self.uri_symbol)
                    attack_tree = LogicalExpression(parent_attack_trees, all_required=True)

                    # All threats are on the threat path
                    parent_threat_trees.append(self.uri_symbol)
                    threat_tree = LogicalExpression(parent_threat_trees, all_required=True)

                    # A threat can be mitigated by
                    # OR(
                    #   inactive control strategies located at itself
                    #   mitigations of any of its parents
                    # )
                    if not self.is_normal_op:
                        # If this threat (self) is on the attack path then it can itself be a mitigation on the attack_path
                        parent_attack_mitigations_cs.append(self.controls)
                        parent_attack_mitigations_csg.append(self.control_strategies)
                    # All threats are a mitigation of the complete threat path
                    parent_threat_mitigations_cs.append(self.controls)
                    parent_threat_mitigations_csg.append(self.control_strategies)

                    attack_mitigated_by_cs = LogicalExpression(parent_attack_mitigations_cs, all_required=False)
                    threat_mitigated_by_cs = LogicalExpression(parent_threat_mitigations_cs, all_required=False)
                    attack_mitigated_by_csg = LogicalExpression(parent_attack_mitigations_csg, all_required=False)
                    threat_mitigated_by_csg = LogicalExpression(parent_threat_mitigations_csg, all_required=False)

            else:
                # we are a misbehaviour with direct causes
                loopback_node_uris = self.all_direct_cause_uris & current_path
                sorted_causes = sorted(list(self.all_direct_cause_uris - current_path))
                logging.debug("  " * len(current_path) + "  " + str(len(sorted_causes)) + " direct causes of MS not in current path")
                for parent_uri in sorted_causes:
                    parent = self.nodes.get_or_create_node(parent_uri)
                    try:
                        p_result = parent.backtrace(current_path, compute_logic)
                    except TreeTraversalError as error:
                        loopback_node_uris |= error.loopback_node_uris
                        # loopback_node_uris.add(parent_uri)
                    else:
                        valid_parent_uris.add(parent_uri)
                        loopback_node_uris |= p_result['loopback_node_uris']
                        all_cause_uris |= p_result['all_cause_uris']
                        # When working out the distance from root, we don't want to count secondary threats, or MS caused by secondary threats
                        if parent.is_secondary_threat:
                            distance_increment = 0
                        else:
                            distance_increment = 1
                        parent_min_distances_from_root.append(p_result['min_distance'] + distance_increment)
                        parent_max_distances_from_root.append(p_result['max_distance'] + distance_increment)
                        parent_primary_threat_routes.append(p_result['primary_threat_route'])
                        parent_root_causes.append(p_result['root_cause'])

                        if compute_logic:
                            p_attack_mitigation_cs, p_threat_mitigation_cs, p_attack_mitigation_csg, p_threat_mitigation_csg, p_attack_tree, p_threat_tree = p_result['data']
                            parent_threat_mitigations_cs.append(p_threat_mitigation_cs)  # Entire path
                            parent_threat_mitigations_csg.append(p_threat_mitigation_csg)  # Entire path
                            parent_threat_trees.append(p_threat_tree)
                            if not parent.is_normal_op:
                                parent_attack_mitigations_cs.append(p_attack_mitigation_cs)  # Just attack path
                                parent_attack_mitigations_csg.append(p_attack_mitigation_csg)  # Just attack path
                                parent_attack_trees.append(p_attack_tree)

                if len(valid_parent_uris) == 0:
                    # Then all parents have thrown exceptions or were on the current path
                    logging.debug("  " * len(current_path) + "  ** misbehaviour {} has all parents invalid".format(str(self.uri).split('#')[1]))
                    raise TreeTraversalError(loopback_node_uris)

                # The root_cause of a misbehaviour is any (OR) of the root causes of its parents
                root_cause = LogicalExpression(parent_root_causes, all_required=False)

                # The minimum distance from a root cause is therefore the minimum of the parent distances
                min_distance_from_root = min(parent_min_distances_from_root)
                max_distance_from_root = max(parent_max_distances_from_root)

                # Take the first shortest route
                primary_threat_route = parent_primary_threat_routes[0]
                for route in parent_primary_threat_routes[1:]:
                    if len(route) < len(primary_threat_route):
                        primary_threat_route = route

                logging.debug("  " * len(current_path) + "  Finished looking at MS causes for {} (min: {}, max: {}, {} valid parents: {})".format(str(self.uri).split('#')[1], str(min_distance_from_root), str(max_distance_from_root), str(len(valid_parent_uris)), str([str(u).split('#')[1] for u in valid_parent_uris])))

                if compute_logic:
                    # The attack/threat path is
                    # OR(
                    #   all the parent threat paths
                    # )
                    attack_tree = LogicalExpression(parent_attack_trees, all_required=False)
                    threat_tree = LogicalExpression(parent_threat_trees, all_required=False)

                    # Misbehaviours can be mitigated by
                    # AND(
                    #   mitigations of their parents
                    # )
                    attack_mitigated_by_cs = LogicalExpression(parent_attack_mitigations_cs, all_required=True)
                    threat_mitigated_by_cs = LogicalExpression(parent_threat_mitigations_cs, all_required=True)
                    attack_mitigated_by_csg = LogicalExpression(parent_attack_mitigations_csg, all_required=True)
                    threat_mitigated_by_csg = LogicalExpression(parent_threat_mitigations_csg, all_required=True)

        except TreeTraversalError as error:
            loopback_node_uris = error.loopback_node_uris
            loopback_node_uris_on_path = (current_path & loopback_node_uris)  # current_path includes self
            loopback_node_uris_on_path.discard(self.uri)  # just look at the path to self, not self itself
            if len(loopback_node_uris_on_path) == 0:
                # the path to self did not constrain the search of self's causes, the cause was just invalid
                # as there were no constraints in play, it will never succeed
                self.cannot_be_caused = True
                result = {}
                logging.debug("  " * len(current_path) + "  Error: {} can never be caused".format(str(self.uri).split('#')[1]))
            else:
                result = {
                    'loopback_node_uris': loopback_node_uris_on_path
                }
                logging.debug("  " * len(current_path) + "  Error: {} could not be caused because of node(s) on the path: {}".format(str(self.uri).split('#')[1], str([str(u).split('#')[1] for u in loopback_node_uris_on_path])))
            self.no_cause_results.append(result)
            self.no_cause_visits += 1
            raise TreeTraversalError(loopback_node_uris_on_path)  # the meaning of the exception argument is the set of nodes on the path to self that constrained the search of self's cause, and ultimately caused it to fail

        else:

            # If we've got this far then the node is on a workable path

            self.not_a_cause = False  # Set to "True" on initialisation but not elsewhere, so this means that the node is on *at least one* workable path

            # Keep track of which direct cause Nodes enabled this Node (also adds this node as an effect of the cause)
            self.add_direct_cause_uris(valid_parent_uris)  # TODO: this should be keyed by target_MS shouldn't it? Probably other things too...

            # Add the direct causes to the accumulated direct causes' causes
            all_cause_uris |= valid_parent_uris

            loopback_node_uris.discard(self.uri)

            # At this point we have a distance_from_root, root_cause and mitigation for the current_path.
            # We return those to be used in the child that called this method on this node, but before that
            # we need to merge the results with any others that have previously been found from other paths to this node.
            # Interestingly, when combining causes over different paths, the logic is reversed.

            self.root_cause = LogicalExpression([self.root_cause, root_cause], all_required=False)

            # Save the max and min distances from this root cause
            # The max is useful to spread things out for display
            # The min is useful to find shortest paths
            self.max_distance_from_root_by_cause[root_cause] = max(self.max_distance_from_root_by_cause.get(root_cause, -1), max_distance_from_root)
            self.min_distance_from_root_by_cause[root_cause] = min(self.max_distance_from_root_by_cause.get(root_cause, INFINITY), min_distance_from_root)

            # Although tempting to calculate the distance from target here, we can't because we don't know if the current tree is going to be successful all the way back to the target.

            self.min_primary_threat_route = primary_threat_route  # TODO: key this by target?

            if compute_logic:
                self.attack_tree_mitigation_cs = LogicalExpression([self.attack_tree_mitigation_cs, attack_mitigated_by_cs], all_required=True)
                self.threat_tree_mitigation_cs = LogicalExpression([self.threat_tree_mitigation_cs, threat_mitigated_by_cs], all_required=True)
                self.attack_tree_mitigation_csg = LogicalExpression([self.attack_tree_mitigation_csg, attack_mitigated_by_csg], all_required=True)
                self.threat_tree_mitigation_csg = LogicalExpression([self.threat_tree_mitigation_csg, threat_mitigated_by_csg], all_required=True)
                self.attack_tree = LogicalExpression([self.attack_tree, attack_tree], all_required=False)
                self.threat_tree = LogicalExpression([self.threat_tree, threat_tree], all_required=False)

            result = {
                'loopback_node_uris': loopback_node_uris,
                'all_cause_uris': all_cause_uris,
                'max_distance': max_distance_from_root,
                'min_distance': min_distance_from_root,
                'root_cause': root_cause,
                'primary_threat_route': primary_threat_route
            }

            if compute_logic:
                result["data"] = (attack_mitigated_by_cs, threat_mitigated_by_cs, attack_mitigated_by_csg, threat_mitigated_by_csg, attack_tree, threat_tree)

            self.cause_results.append(result)
            self.cause_visits += 1
            return result

class Timer():
    def __init__(self):
        self.stime = time.perf_counter()

    def log(self):
        etime = time.perf_counter()
        print(f"-- Duration: {etime - self.stime:0.2f} seconds")
        self.stime = time.perf_counter()

# TODO: this needs to change to use the new predicates rather than rely on string matching
def is_current_risk_csg(csg_uriref):
    # accept just -Runtime, -Implementation and -Implementation-Runtime
    return ("-Runtime" in str(csg_uriref)) or ("-Implementation" in str(csg_uriref))

# TODO: this needs to change to use the new predicates rather than rely on string matching
def is_future_risk_csg(csg_uriref):
    # ignore Implementation-Runtime, and -Implementation. Keep "-Runtime".
    return not ("-Implementation-Runtime" in str(csg_uriref) or "-Implementation" in str(csg_uriref))

# TODO: this is broken because the URI can no longer be manipulated this way
def get_contingency_plan_csg(csg_uriref):
    """Given a URIRef of a CSG, return the URIRef of the associated contingency plan CSG (if one exists) or False."""
    if not is_current_risk_csg(csg_uriref):
        return False
    csg_uri = str(csg_uriref)
    if csg_uri.endswith("-Implementation-Runtime"):
        plan_uri = csg_uri[:-23]
    elif csg_uri.endswith("-Implementation"):
        plan_uri = csg_uri[:-15]
    else:
        return False
    plan_uriref = URIRef(plan_uri)
    if not get_is_control_strategy(plan_uriref):
        return False
    return plan_uriref

def has_inactive_contingency_plan(csg_uriref):
    """Test whether there is a contingency plan for the given CSG and if so, whether there are control sets in the CSG that can be proposed and are not proposed."""
    plan_csg = get_contingency_plan_csg(csg_uriref)
    if plan_csg is False:
        return False
    cs = get_csg_inactive_control_set_uris(plan_csg)
    if len(cs) > 0:
        return True
    else:
        return False

def get_threat_control_strategy_uris(threat_uri, future_risk=True):
    """Return list of control strategies (urirefs) that block a threat (uriref)"""
    csg_uris = []
    # the "blocks" predicate means a CSG appropriate for current or future risk calc
    # the "mitigates" predicate means a CSG appropriate for future risk (often a contingency plan for a current risk CSG); excluded from likelihood calc in current risk
    if future_risk:
        for csg_uri in chain(graph.subjects(BLOCKS, threat_uri), graph.subjects(MITIGATES, threat_uri)):
            if is_future_risk_csg(csg_uri):
                # TODO: eventually need to remove this hack and just append the csg_uri
                csg_uris.append(MyControlStrategy.get_or_create_csg(csg_uri))
    else:
        for csg_uri in graph.subjects(BLOCKS, threat_uri):
            if is_current_risk_csg(csg_uri) and not has_inactive_contingency_plan(csg_uri):
                # TODO: eventually need to remove this hack and just append the csg_uri
                csg_uris.append(MyControlStrategy.get_or_create_csg(csg_uri))
    return csg_uris

def get_threat_inactive_control_strategies(threat_uri, future_risk=True):
    csg_uris = []
    for csg_uri in get_threat_control_strategy_uris(threat_uri, future_risk):
        cs_uris = get_csg_inactive_control_set_uris(csg_uri)
        if len(cs_uris) > 0:
            csg_uris.append(csg_uri)
    return csg_uris

def get_csg_control_set_uris(csg_uri):
    """Return a list of control sets (urirefs) that are part of a control strategy (uriref)"""
    # TODO: eventually need to remove this hack
    if isinstance(csg_uri, MyControlStrategy):
        csg_uri = csg_uri.original_uriref

    css = []
    for cs in graph.objects(csg_uri, HAS_MANDATORY_CONTROL_SET):
        css.append(cs)
    return css

def get_csg_inactive_control_set_uris(csg_uri):
    """Return a list of control sets (urirefs) that are part of a control strategy (uriref) but are inactive and assertable."""
    css = []
    for cs in get_csg_control_set_uris(csg_uri):
        asset = graph.value(cs, LOCATED_AT)
        asset_type = graph.value(asset, HAS_TYPE).split('#')[1]
        control_type = graph.value(cs, HAS_CONTROL).split('#')[1]
        cas = "CAS-{}-{}".format(control_type, asset_type)
        is_assertable = ca_settings.get(cas, False)  # SSM generates some stupid control sets which should be taken as unassertable and ignored

        is_proposed = graph.value(cs, IS_PROPOSED, default=False)

        # If a control is proposed then is_proposed == rdflib.term.Literal('true', datatype=rdflib.term.URIRef('http://www.w3.org/2001/XMLSchema#boolean'))
        # "not" of that is False and "not" of the 'false' literal is True so the next line holds:

        if not is_proposed and not is_assertable:
            # if any of the CS in a CSG is not assertable and is not proposed then the whole CSG cannot be activated
            return []

        if not is_proposed and is_assertable:
            css.append(cs)
    return css

def get_csg_asset_uris(csg_uri):
    cs_uris = get_csg_control_set_uris(csg_uri)
    asset_uris = []
    for cs_uri in cs_uris:
        asset_uris.append(graph.value(cs_uri, LOCATED_AT))
    return asset_uris

def get_csg_asset_labels(csg_uri):
    labels = []
    for asset in get_csg_asset_uris(csg_uri):
        labels.append(graph.value(asset, HAS_LABEL))
    return labels

def get_threat_direct_cause_uris(threat_uri):
    """Return a list of urirefs which are the direct causes (misbehaviours) of a threat"""
    direct_cause_uris = []
    for direct_cause in graph.subjects(CAUSES_THREAT, threat_uri):
        direct_cause_uris.append(direct_cause)
    return direct_cause_uris

def get_misbehaviour_direct_cause_uris(misb_uri):
    """Return a list of urirefs which are the direct causes (threats) of a misbehaviour"""
    direct_cause_uris = []
    for threat in graph.subjects(CAUSES_DIRECT_MISBEHAVIOUR, misb_uri):
        direct_cause_uris.append(threat)
    return direct_cause_uris

def get_likelihood_number(uriref):
    """Return likelihood level of a threat or misbehaviour uriref as a number from 0 to 4, or -1 if no likelihood is defined
    
    Caches the level in global _likelihood dictionary
    """
    try:
        # TODO: probably don't need this cache
        return _likelihood[uriref]  # global!
    except:
        like = _get_likelihood(uriref)
        # TODO: the scales are now defined in the domain model so need to load the strings from there
        level = {"VeryLow": 0, "Low": 1, "Medium": 2, "High": 3, "VeryHigh": 4, "None": -1}[like]
        _likelihood[uriref] = level
        return level

def get_likelihood_text(uriref):
    return un_camel_case(_get_likelihood(uriref))

def _get_likelihood(uriref):
    try:
        level = graph.value(uriref, HAS_LIKELIHOOD)
        # level is e.g. http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#LikelihoodVeryLow
        return str(level).split('#')[-1][10:]
    except:
        return "None"

def get_impact_text(uriref):
    return un_camel_case(_get_impact(uriref))

def _get_impact(uriref):
    try:
        level = graph.value(uriref, HAS_IMPACT)
        # level is e.g. http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#ImpactLevelMedium
        return str(level).split('#')[-1][11:]
    except:
        return "None"

def get_risk_text(uriref):
    return un_camel_case(_get_risk(uriref))

def _get_risk(uriref):
    try:
        level = graph.value(uriref, HAS_RISK)
        # level is e.g. http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelMedium
        return str(level).split('#')[-1][9:]
    except:
        return "None"

def get_trustworthiness_text(uriref):
    return un_camel_case(_get_trustworthiness(uriref))

def _get_trustworthiness(uriref):
    try:
        tw = graph.value(uriref, HAS_INFERRED_LEVEL)
        # level is e.g. http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelVeryLow
        return str(tw).split('#')[-1][20:]
    except:
        return "None"

def get_is_control_strategy(uriref):
    return ((uriref, BLOCKS, None) in graph) or ((uriref, MITIGATES, None) in graph)

def get_is_normal_op(uriref):
    """Return Boolean describing if the uriref refers to a normal operation threat or misbehaviour"""
    if get_is_threat(uriref):
        return (uriref, IS_NORMAL_OP, Literal(True)) in graph
    else:
        return (uriref, IS_NORMAL_OP_EFFECT, Literal(True)) in graph

def get_is_root_cause(uriref):
    """Return Boolean describing if the uriref refers to a root cause threat"""
    return (uriref, IS_ROOT_CAUSE, Literal(True)) in graph

def get_is_threat(uriref):
    """Return Boolean describing if the uriref refers to a primary OR secondary threat"""
    return (uriref, HAS_TYPE, THREAT) in graph

def get_is_secondary_threat(uriref):
    """Return Boolean describing if the uriref refers to a secondary threat"""
    # TODO: some threats now have mixed causes, does this, or the use of this need to change?
    return (uriref, HAS_SECONDARY_EFFECT_CONDITION, None) in graph  # tests if there is a triple (threat, has_secondary_effect_condition, <anything>)

def get_is_primary_threat(uriref):
    """Return Boolean describing if the uriref refers to a primary threat"""
    # TODO: some threats now have mixed causes, does this, or the use of this need to change?
    return get_is_threat(uriref) and not get_is_secondary_threat(uriref)

def get_is_external_cause(uriref):
    """Return Boolean describing if the uriref refers to an external cause misbehaviour"""
    return (uriref, IS_EXTERNAL_CAUSE, Literal(True)) in graph

def get_is_initial_cause(uriref):
    """Return Boolean describing if the uriref refers to an initial cause threat"""
    return (uriref, IS_INITIAL_CAUSE, Literal(True)) in graph

def get_is_misbehaviour_set(uriref):
    """Return Boolean describing if the uriref refers to a misbehaviour set"""
    return (uriref, HAS_TYPE, MISBEHAVIOUR_SET) in graph

def get_is_misbehaviour_on_asserted_asset(ms_uriref):
    """Return Boolean describing if the uriref refers to a misbehaviour located at an asserted asset"""
    if get_is_threat(ms_uriref):
        return False
    else:
        for asset_uriref in graph.objects(ms_uriref, LOCATED_AT):
            if get_is_asserted_asset(asset_uriref):
                return True
        return False

def get_is_asserted_asset(asset_uriref):
    """Return Boolean describing whether the uriref refers to an asserted asset"""
    # There should only be 1 triple matching this, but I can't see another way to just query the asserted graph
    for dummy, dummy, type in graph.triples((asset_uriref, HAS_TYPE, None, asserted_graph)):
        if type.startswith(DOMAIN):
            return True
    return False

def get_is_default_tw(twas_uriref):
    """Return Boolean describing whether the uriref refers to a TWAS which has the Default TW attribute"""
    return (twas_uriref, HAS_TWA, DEFAULT_TW_ATTRIBUTE) in graph

def get_is_in_service(threat_uriref):
    for cause_uriref in graph.subjects(CAUSES_THREAT, threat_uriref):
        if get_is_default_tw(cause_uriref):
            return True
    return False

def get_misbehaviour_location_uri(ms_uriref):
    """Return the asset URIs that the misbehaviour has an effect on"""
    if not get_is_threat(ms_uriref):
        return graph.value(ms_uriref, LOCATED_AT)

def get_threat_involved_asset_uris(threat_uriref):
    """Return a list of urirefs of the assets that are in a threat's matching pattern"""
    assets = []
    for matching_pattern in graph.objects(threat_uriref, APPLIES_TO):
        for node in graph.objects(matching_pattern, HAS_NODE):
            for asset in graph.objects(node, HAS_ASSET):
                assets.append(asset)
    return assets

# TODO: make it operate on the display graph, not the ThreatTree
def add_node_indices(self, i=0, node=None):
    if node == None:
        for root_uri in self.root_causes:
            i = self.add_node_indices(i, self[root_uri])
    else:
        if not node.index:
            node.index = i
            logging.debug("{}|{}".format(i, node.comment))
            i += 1
            for child_uri in node.direct_effect_uris:
                i = self.add_node_indices(i, self[child_uri])
    return i

def unzip_gz_file(filename):
    if not filename.lower().endswith('.gz'):
        return filename

    # Create a temporary file to store the unzipped data
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_filename = temp_file.name

    try:
        # Open the gzipped file and the temporary file
        with gzip.open(filename, 'rb') as gz_file, open(temp_filename, 'wb') as temp:
            # Read from the gzipped file and write to the temporary file
            temp.write(gz_file.read())

        print(f"Unzipped NQ file into temporary file: {temp_filename}")
        return temp_filename

    except Exception as e:
        print(f"Error while unzipping: {e}")

print("Loading domain model misbehaviours...", end="")
misbehaviours = load_domain_misbehaviours(domain_misbehaviours_filename)
print(len(misbehaviours))

print("Loading domain model trustworthiness attributes...", end="")
trustworthiness_attributes = load_domain_trustworthiness_attributes(domain_trustworthiness_attributes_filename)
print(len(misbehaviours))

print("Loading domain model controls...", end="")
controls = load_domain_controls(domain_controls_filename)
print(len(controls))

print("Loading domain model control strategies...", end="")
control_strategies = load_domain_control_strategies(domain_control_strategies_filename)
print(len(control_strategies))

print("Loading domain model CA Settings...", end="")
ca_settings = load_domain_ca_settings(domain_ca_settings_filename)
print(len(ca_settings))

nq_filename = unzip_gz_file(nq_filename)

graph = ConjunctiveGraph()
print("Loading nq file...", end="")
timer = Timer()
graph.parse(nq_filename, format="nquads")
print(len(graph))
timer.log()

# look through the different graphs contained in the nq file
for context in graph.store.contexts():
    # find the one that has not got "/ui" or "/inf" or anything else on the end
    if context.identifier.count("/") == 4:
        asserted_graph = context.identifier

_likelihood = {}

target_ms_uris = [URIRef(SYSTEM + "#" + target_ms_id) for target_ms_id in target_ms_ids]

print("Finding paths to effect(s)...", end="")
threat_tree = ThreatTree(target_ms_uris, FUTURE_RISK, LIMIT_LOGIC_TO_SHORTEST_PATH)
node_uris = set(threat_tree.uris)
print(str(len(node_uris)) + " nodes")

timer.log()

print('Preparing plot nodes...')

# Add distance of each node from each target MS
# TODO: need to make this work for when just the shortest path is being displayed. Might need to make a smaller confined ThreatTree and run the add_max_distance_from_target method on that.
for target_ms_uri in target_ms_uris:
    threat_tree.add_max_distance_from_target(target_ms_uri)

nodes = set(threat_tree.nodes)

# TODO: define some simple classes for the display graph instead of using sets and dictionaries?

# Create links between the nodes of the tree using appropriate predicates
links = set()
cause_links_by_node = {}
effect_links_by_node = {}
for node in nodes:
    cause_links_by_node[node] = set()
    effect_links_by_node[node] = set()
for node in nodes:
    for cause_uri in node.direct_cause_uris:
        if node.is_logic:
            predicate = ""
        elif node.is_primary_threat:
            predicate = "enables"
        elif node.is_secondary_threat or node.is_misbehaviour_set:
            predicate = "causes"
        link = (threat_tree[cause_uri], predicate, node)
        links.add(link)
        cause_links_by_node[node].add(link)
        effect_links_by_node[threat_tree[cause_uri]].add(link)    

rank_by_uri = {}

# TODO: the "align" methods here work for when the whole graph is being displayed but if only a subset of nodes is displayed they will cause the plot to be too spread out
if ALIGN_ROOT_CAUSES:
    for node in nodes:
        rank_by_uri[node.uri] = node.max_distance_from_root
    if ALIGN_TARGET_MISBEHAVIOURS:
        raise Exception("Can't align by both root cause and target effect at the same time")

if ALIGN_TARGET_MISBEHAVIOURS:
    for node in nodes:
        rank_by_uri[node.uri] = node.max_distance_from_target

# Find the nodes that are on the shortest path
if HIDE_LONG_ROUTES or HIGHLIGHT_SHORT_ROUTES or csv_debug_filename:
    short_path_nodes = threat_tree.shortest_path_nodes

if csv_debug_filename:
    sorted_nodes = sorted(list(nodes), key=lambda node: node.uri)
    with open(csv_debug_filename, "w") as csv_file:
        for node in sorted_nodes:
            if node in short_path_nodes:
                # this is to match output from Java
                b = "true"
            else:
                b = "false"
            csv_file.write('{}, {}, {}, {}\n'.format(node.uri.split('#')[1], node.min_distance_from_root, node.max_distance_from_root, b))

if HIDE_LONG_ROUTES:
    nodes = set(short_path_nodes)

if HIGHLIGHT_SHORT_ROUTES:
    highlighted_nodes = set(short_path_nodes)
else:
    highlighted_nodes = set(nodes)

# Find the external causes that are directly connected to the attack tree (as we don't want to hide them)
external_causes = [node for node in nodes if node.is_external_cause]
external_causes_of_root_causes = set()
for node in external_causes:
    for effect_uri in node.direct_effect_uris:
        effect_node = threat_tree[effect_uri]
        if effect_node.is_root_cause:
            external_causes_of_root_causes.add(node)

# Hide some nodes in the diplayed graph, joining the parents of the hidden nodes to their children
if HIDE_CONFUSING_MISBEHAVIOURS or HIDE_ALL_MISBEHAVIOURS or HIDE_SECONDARY_THREATS or not SHOW_NORMAL_OPS or not SHOW_EMBEDDED_NORMAL_OPS or not SHOW_EXTERNAL_CAUSES or not SHOW_DEFAULT_TW or not SHOW_INITIAL_CAUSES or not SHOW_IN_SERVICE:
    nodes_to_delete = set()
    for node in nodes:
        if node.is_logic:
            # dealt with after this
            continue
        if node.is_target_ms and len(node.direct_cause_uris) > 0:
            # remove any target MS that are not actually caused, otherwise they are orphaned in plot
            continue
        if node.is_initial_cause:
            if get_is_in_service(node.uri):
                if SHOW_IN_SERVICE:
                    continue
            else:
                if SHOW_INITIAL_CAUSES:
                    continue
        if node.is_external_cause:
            if get_is_default_tw(node.uri):
                if SHOW_DEFAULT_TW:
                    continue
            else:
                if SHOW_EXTERNAL_CAUSES:
                    continue
        if node.is_normal_op:
            if node.min_primary_threat_distance > 0:
                if SHOW_EMBEDDED_NORMAL_OPS:
                    continue
            else:
                if SHOW_NORMAL_OPS:
                    continue
        elif node.is_threat:
            if node.is_secondary_threat:
                if not HIDE_SECONDARY_THREATS:
                    continue
            else:
                # show primary threats
                continue
        else:
            # misbehaviour
            if not HIDE_ALL_MISBEHAVIOURS:
                if get_is_misbehaviour_on_asserted_asset(node.uri):
                    # show MS that are not confusing (i.e. relate to asserted assets)
                    continue
                elif not HIDE_CONFUSING_MISBEHAVIOURS:
                    continue
        nodes_to_delete.add(node)
        cause_links = cause_links_by_node[node]
        effect_links = effect_links_by_node[node]
        for cause_link in cause_links:
            for effect_node in effect_links:
                link = (cause_link[0], effect_node[1], effect_node[2])
                links.add(link)
                cause_links_by_node[effect_node[2]].add(link)
                effect_links_by_node[cause_link[0]].add(link)
    nodes -= nodes_to_delete

# If we've added logic nodes and are hiding things, we need to remove any logic nodes that have become redundant
if (ADD_ANDS or ADD_ORS) and (not SHOW_NORMAL_OPS or not SHOW_EMBEDDED_NORMAL_OPS or HIDE_LONG_ROUTES or HIDE_CONFUSING_MISBEHAVIOURS or HIDE_ALL_MISBEHAVIOURS or HIDE_SECONDARY_THREATS):
    search_again = True
    while search_again:
        nodes_to_delete = set()
        for node in nodes:
            if node.is_logic:
                cause_links_in_graph = [link for link in cause_links_by_node[node] if link[0] in nodes]
                effect_links_in_graph = [link for link in effect_links_by_node[node] if link[2] in nodes]
                # logging.debug("Looking at logic node {} ({} cause links, {} effect links)".format(str(node.uri).split('#')[1], str(len(cause_links_in_graph)), str(len(effect_links_in_graph))))
                # reasons to remove a logic node:
                #   it has no causes in the graph: happens when its logic node in normal-ops graph that's been isolated by normal-ops being hidden
                #   it has 1 cause in the graph: happens all the time because of input nodes being hidden
                #   it is an OR with with an OR as its child (there is only 1 child of a logic node)
                #   it is an AND with an AND as its child
                if len(cause_links_in_graph) < 2 or (node.is_or and effect_links_in_graph[0][2].is_or) or (node.is_and and effect_links_in_graph[0][2].is_and):
                    nodes_to_delete.add(node)
                    links_to_add = set()
                    links_to_delete = set()
                    for cause_link in cause_links_in_graph:
                        links_to_delete.add(cause_link)
                        for effect_node in effect_links_in_graph:
                            links_to_delete.add(effect_node)
                            links_to_add.add((cause_link[0], effect_node[1], effect_node[2]))
                    for link in links_to_delete:
                        cause_links_by_node[link[2]].remove(link)
                        effect_links_by_node[link[0]].remove(link)
                    for link in links_to_add:                                                
                        links.add(link)
                        cause_links_by_node[link[2]].add(link)
                        effect_links_by_node[link[0]].add(link)
        nodes -= nodes_to_delete
        if len(nodes_to_delete) == 0:
            search_again = False

if SHOW_BLOBS:
    # TODO: this needs to traverse the reduced "nodes" set
    threat_tree.add_node_indices()

timer.log()

# plot_graph plots all the nodes and any links between nodes that are in "links"
# therefore we don't need to remove links from "links" that go to nodes that we've removed
plot_graph(
    filename=output_filename,
    nodes_to_plot=nodes,
    links_to_plot=links,
    rank_by_uri=rank_by_uri,
    highlighted_nodes=highlighted_nodes
)

timer.log()

# Loop over target MS and print attack graph and threat graph CS/CSG expression for each

if le_debug_filename:
    with open(le_debug_filename, "w") as le_file:

        for target in target_ms_uris:
            node = threat_tree[target]
            le_file.write("Logical expressions for {} ({}):\n".format(node.comment, target))
            le_file.write("- Attack graph CS:\n\n{}\n".format(node.attack_tree_mitigation_cs.pretty_print(max_complexity=600)))
            le_file.write("- Attack graph CSG:\n\n{}\n".format(node.attack_tree_mitigation_csg.pretty_print(max_complexity=600)))
            le_file.write("- Threat graph CS:\n\n{}\n".format(node.threat_tree_mitigation_cs.pretty_print(max_complexity=600)))
            le_file.write("- Threat graph CSG:\n\n{}\n".format(node.threat_tree_mitigation_csg.pretty_print(max_complexity=600)))

        le_file.write("\nAll CSGs involved in attack graph (" + str(len(threat_tree.attack_graph_mitigation_csg.uris)) + "):\n")
        csgs = [get_comment(csg_uri) for csg_uri in threat_tree.attack_graph_mitigation_csg.uris]
        csgs.sort()
        for csg in csgs:
            le_file.write(csg)

        le_file.write("\nAll CSGs involved in threat graph (" + str(len(threat_tree.threat_graph_mitigation_csg.uris)) + "):\n")
        csgs = [get_comment(csg_uri) for csg_uri in threat_tree.threat_graph_mitigation_csg.uris]
        csgs.sort()
        for csg in csgs:
            le_file.write(csg)

        # Combine the expressions across all the target MS

        le_file.write("\nCS expression for all target misbehaviours in attack graph:\n")
        le_file.write(threat_tree.attack_graph_mitigation_cs.pretty_print(max_complexity=600))

        le_file.write("\nCSG expression for all target misbehaviours in attack graph:\n")
        le_file.write(threat_tree.attack_graph_mitigation_csg.pretty_print(max_complexity=600))

        le_file.write("\nCS expression for all target misbehaviours in threat graph:\n")
        le_file.write(threat_tree.threat_graph_mitigation_cs.pretty_print(max_complexity=600))

        le_file.write("\nCSG expression for all target misbehaviours in threat graph:\n")
        le_file.write(threat_tree.threat_graph_mitigation_csg.pretty_print(max_complexity=600))

        timer.log()
