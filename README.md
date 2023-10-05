# Plot Attack Tree

This software creates a graphical attack tree for a Spyderisk system model. Strictly the "attack tree" is actually a "graph" (in that it can contain loops), it can also include nodes that are part of the normal operation model of a system as well as threats involved in a potential attack.

## Pre-requisites

Python 3 is required, along with the 3rd-party libraries described in the `requirements.txt` file. The libraries can be installed with Python `pip` using `pip install -r requirements.txt`. You may wish to use a Python virtual environment to isolate the dependencies.

## Usage

```
usage: plot-attack-tree.py [-h] -i input_NQ_filename -o output_image_filename -d CSV_directory -m URI_fragment [URI_fragment ...]
                           [--plot-direction {BT,TB,RL,LR}] [--current-risk] [--limit-logic] [--and] [--or] [--all-routes]
                           [--highlight-short-routes] [--normal-ops] [--embedded-normal-ops] [--external-causes] [--default-tw]
                           [--initial-causes] [--in-service] [--hide-confusing-misbehaviours] [--hide-misbehaviours]
                           [--hide-secondary-threats] [--constrain-arrows] [--align-root-causes] [--align-target-misbehaviours]
                           [--blobs] [--compact] [--hide-link-labels] [--hide-command] [--uris] [--distance-from-root]
                           [--primary-threat-distance] [--attack-graph-controls] [--threat-graph-controls]
                           [--attack-graph-control-strategies] [--threat-graph-control-strategies] [--threat-description]
                           [--misbehaviour-description] [--hide-node-titles] [--hide-likelihood-in-description] [--text-width integer]
                           [--debug-csv filename] [--debug-logical-expressions filename] [--version]
```

Mandatory arguments:

```
  -i input_NQ_filename, --input input_NQ_filename
                        Filename of the validated system model NQ file (compressed or not)
  -o output_image_filename, --output output_image_filename
                        Output filename (PDF, SVG or PNG)
  -d CSV_directory, --domain CSV_directory
                        Directory containing the domain model CSV files
  -m URI_fragment [URI_fragment ...], --misbehaviour URI_fragment [URI_fragment ...]
                        Target misbehaviour IDs, e.g. 'MS-LossOfControl-f8b49f60'
```

Optional arguments affecting the graph to be plotted:

```
  --plot-direction {BT,TB,RL,LR}
                        The direction of the plot from causes to effects (B=bottom, T=top, L=left, R=right)
  --current-risk        Run in current (not future) risk mode, affecting the control strategies proposed
  --limit-logic         Compute the logical expressions to only target nodes on the shortest paths
  --and                 Add explicit AND nodes to the displayed graph
  --or                  Add explicit OR nodes to the displayed graph
  --all-routes          Show all routes through the graph, not just the shortest
  --highlight-short-routes
                        Highlight the shortest routes through the graph if all routes are shown
  --normal-ops          Show the normal operation graph (apart from embedded normal ops)
  --embedded-normal-ops
                        Show normal operation nodes embedded in the attack graph
  --external-causes     Show the external causes (apart from 'DefaultTW' ones)
  --default-tw          Show the 'DefaultTW' external causes
  --initial-causes      Show the initial causes (apart from 'InService' ones)
  --in-service          Show the 'InService' initial causes
  --hide-confusing-misbehaviours
                        Hide misbehaviours relating to inferred assets
  --hide-misbehaviours  Hide all misbehaviour nodes
  --hide-secondary-threats
                        Hide secondary threats in the graph
  --constrain-arrows    Force the arrows to enter/leave the nodes at the top/bottom (or left/right)
  --align-root-causes   Align the root causes
  --align-target-misbehaviours
                        Align the target misbehaviours
  --blobs               Show all nodes as circles with no content
  --compact             Make the plot more compact by reducing margins between nodes
  --hide-link-labels    Hide the labels on the arrows connecting the nodes
  --hide-command        Hide the command line from the plot
```

Optional arguments which determine what content is displayed within each node (threat or misbehaviour):

```
  --uris                Show the URI of each node
  --distance-from-root  Show the distance from the root cause on a node
  --primary-threat-distance
                        Show the number of primary threats needed to get to each node
  --attack-graph-controls
                        Show logical expressions for controls that block the attack graph on each node
  --threat-graph-controls
                        Show logical expressions for controls that block the threat graph on each node
  --attack-graph-control-strategies
                        Show logical expressions for controls strategies that block the attack graph on each node
  --threat-graph-control-strategies
                        Show logical expressions for controls strategies that block the threat graph on each node
  --threat-description  Show the long threat descriptions
  --misbehaviour-description
                        Show the long misbehaviour descriptions
  --hide-node-titles    Hide the titles on the nodes
  --hide-likelihood-in-description
                        Hide the likelihood in the node descriptions
  --text-width integer  Character-width of the text in nodes
  --debug-csv filename  Filename to dump CSV formatted node information for debugging
  --debug-logical-expressions filename
                        Filename to write logical expressions for target consequences into
```

Other arguments:

```
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

For example:

1. Examine your system model in the Spyderisk System Modeller to choose which *consequences* you want to see the attack path for.
   1. Enter "developer mode" in Spyderisk System Modeller by pressing `Ctrl-#`.
   2. For each *consequence* of interest, open the "Consequence Explorer" and note down the end fragment of its URI (displayed at the top of the Explorer).
2. Ensure your system model is validated, and then export your system model from the Spyderisk System Modeller choosing the "full model" option (it will have file extension `.nq.gz`, for example `SteelMill.nq.gz`).
3. Obtain the version of the domain model used by your system model, for instance by cloning [https://github.com/Spyderisk/domain-network].
4. Execute the following command, including the location of the domain model CSV folder and the *consequence* URI fragments previously noted to get a PDF file containing a graphical attack tree showing the shortest and most likely ways that the two *consequences* (also known as "misbehaviours") can be caused:

```shell
plot-attack-tree.py -i SteelMill.nq.gz -o steel.pdf -d ../domain-network/csv/ -m MS-LossOfControl-f8b49f60 MS-LossOfReliability-f8b49f60 --and --or --hide-misbehaviours --hide-secondary-threats --external-causes --initial-causes --hide-link-labels --hide-likelihood-in-description --hide-node-titles --compact --text-width 30
```

## Contributors

The software was written by [Stephen C. Phillips](https://github.com/scp93ch) with some assistance from [Mike Surridge](https://github.com/mike1813).

## Licence

The software is Copyright 2023 University of Southampton IT Innovation Centre and licensed under the Apache 2.0 license.

### 3rd Party Libraries

At time of writing, the licenses of the 3rd party dependencies are:

```
 Name           Version  License
 boolean.py     3.8      BSD-2-Clause
 graphviz       0.18     MIT License
 isodate        0.6.1    BSD License
 pyparsing      3.1.1    MIT License
 rdflib         6.0.2    BSD License
 six            1.16.0   MIT License
```
