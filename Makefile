include /usr/local/etc/PcapPlusPlus.mk




# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) -c $(PCAPPP_INCLUDES) -c -o build/main.o src/main.cpp -lyaml-cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/Protocol_Analysis  build/main.o $(PCAPPP_LIBS) -lyaml-cpp

	g++ $(PCAPPP_BUILD_FLAGS) -c $(PCAPPP_INCLUDES) -c -o build/receiver_test.o src/receiver_test.cpp -lyaml-cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/receiver_test  build/receiver_test.o $(PCAPPP_LIBS) -lyaml-cpp

# Clean Target
clean:
	rm -rf debug_data_output/*.txt
	rm build/main.o
	rm build/Protocol_Analysis
	rm build/receiver_test.o
	rm build/receiver_test



