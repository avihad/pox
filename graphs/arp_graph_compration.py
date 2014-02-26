__author__ = 'avihad'

import pygal


def regular_arp_graph():
    number_of_nodes = range(5, 100, 2)
    num_of_arp_msgs = {k: ((k ** 3 - k ** 2) / 2) for k in number_of_nodes}
    chart = pygal.XY(title="Number of ARP-Message in a simple flooding algorithm" , x_title = "Number of hosts" , y_title = "Number of ARP-Messages")
    chart.add("values", num_of_arp_msgs.items())
    chart.render_to_file("simple_flooding.svg")

def improved_arp_algorithm_graph():
    number_of_nodes = range(5, 100, 2)
    num_of_arp_msgs = {k: (k ** 2 + k - 2) for k in number_of_nodes}
    chart = pygal.XY(title="Number of ARP-Message in our implemented algorithm" , x_title = "Number of hosts" , y_title = "Number of ARP-Messages")
    chart.add("values", num_of_arp_msgs.items())
    chart.render_to_file("controller_arp_response.svg")

def main():
    print("Before calculating ARP graphs")
    regular_arp_graph()
    improved_arp_algorithm_graph()
    print("After calculating ARP graphs")

if __name__ == '__main__':
    main()