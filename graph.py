import networkx as nx
import matplotlib.pyplot as plt

def draw_network(devices):
    G = nx.Graph()

    main_node = "Router"
    G.add_node(main_node)

    for d in devices:
        G.add_node(d)
        G.add_edge(main_node, d)

    nx.draw(G, with_labels=True, node_color='lightblue', node_size=2000, font_size=8)

    plt.savefig("static/network.png")
    plt.clf()