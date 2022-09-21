from  .metadata import print_stats

def main():
    """
    cvedata module main function
    """
    print_stats()

    print("To update data run: python -m cvedata.update")


if __name__ == "__main__":
    main()